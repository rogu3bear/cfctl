//! Stable error taxonomy and recovery guidance for the runtime boundary.

use thiserror::Error;

use super::prelude::{CapabilityV1, CloudflareResponseV1, Value, json};

#[derive(Debug, Error)]
pub enum CliError {
    #[error("{0}")]
    Input(String),
    #[error("I/O failed for {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error(transparent)]
    Storage(#[from] cfctl_storage::StorageError),
    #[error(transparent)]
    Catalog(#[from] cfctl_catalog::CatalogError),
    #[error(transparent)]
    Auth(#[from] cfctl_auth::AuthError),
    #[error(transparent)]
    Core(#[from] cfctl_core::CoreError),
    #[error(transparent)]
    Cloudflare(#[from] cfctl_cloudflare::CloudflareError),
    #[error(transparent)]
    Workspace(#[from] cfctl_workspace::WorkspaceError),
    #[error(transparent)]
    Registry(#[from] cfctl_registry::RegistryError),
    #[error(transparent)]
    Agent(#[from] cfctl_agent::AgentError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("HTTP client construction failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("subprocess `{label}` exceeded the {timeout_seconds}-second governed timeout")]
    SubprocessTimeout { label: String, timeout_seconds: u64 },
    #[error("delegated mutation subprocess `{label}` was not started")]
    SubprocessNotStarted { label: String },
    #[error(
        "delegated mutation subprocess `{label}` started, but no complete receipt is available"
    )]
    SubprocessReceiptUnavailable { label: String },
    #[error("delegated mutation was not attempted: {message}")]
    DelegatedMutationNotAttempted { message: String },
    /// A CLI-level blocker that carries its own stable code and a specific,
    /// copy-pasteable next command for the agent. Prefer this over
    /// `Input(String)` whenever the failure has a knowable recovery step.
    #[error("{message}")]
    Guided {
        code: &'static str,
        message: String,
        next_step: String,
    },
}

impl CliError {
    /// Build a guided blocker: a stable code, a human message, and the exact
    /// next command an agent should run to recover.
    pub fn guided(
        code: &'static str,
        message: impl Into<String>,
        next_step: impl Into<String>,
    ) -> Self {
        Self::Guided {
            code,
            message: message.into(),
            next_step: next_step.into(),
        }
    }

    /// Stable machine-readable code for the failure envelope. Defaults to
    /// `CFCTL_ERROR` when the category is not specifically recognized.
    #[must_use]
    pub fn code(&self) -> &'static str {
        self.guidance().map_or("CFCTL_ERROR", |(code, _)| code)
    }

    /// A specific, copy-pasteable next command for the agent, when the error
    /// category makes one knowable. `None` lets the caller fall back to the
    /// generic doctor guidance.
    #[must_use]
    pub fn next_step(&self) -> Option<String> {
        self.guidance().map(|(_, step)| step)
    }

    fn guidance(&self) -> Option<(&'static str, String)> {
        match self {
            Self::Guided {
                code, next_step, ..
            } => Some((code, next_step.clone())),
            Self::Cloudflare(inner) => cloudflare_guidance(inner),
            Self::Core(inner) => core_guidance(inner),
            Self::Storage(inner) => storage_guidance(inner),
            Self::Auth(inner) => auth_guidance(inner),
            Self::Workspace(_) => Some((
                "CFCTL_WORKSPACE",
                "Run `cfctl workspace audit --json` to inspect registered roots and drift."
                    .to_owned(),
            )),
            Self::Registry(_) => Some((
                "CFCTL_REGISTRY",
                "Run `cfctl registry status --json` and `cfctl registry coverage --json` to inspect projection health and blockers."
                    .to_owned(),
            )),
            Self::SubprocessTimeout { .. } => Some((
                "CFCTL_SUBPROCESS_TIMEOUT",
                "The governed subprocess did not return a complete receipt. If this occurred during `plans run`, inspect `cfctl plans status <operation-id> --json`; do not assume the plan was consumed or replay the mutation until durable status proves the correct recovery path."
                    .to_owned(),
            )),
            Self::SubprocessReceiptUnavailable { .. } => Some((
                "CFCTL_SUBPROCESS_RECEIPT_UNAVAILABLE",
                "The mutation-capable subprocess started but did not return a complete receipt. Inspect `cfctl plans status <operation-id> --json`, then use its exact disposition; do not replay the mutation."
                    .to_owned(),
            )),
            Self::SubprocessNotStarted { .. } | Self::DelegatedMutationNotAttempted { .. } => {
                Some((
                    "CFCTL_DELEGATED_MUTATION_NOT_ATTEMPTED",
                    "The mutation-capable subprocess was not started. Inspect `cfctl plans status <operation-id> --json` and the local blocker; do not infer a provider write from plan consumption alone."
                        .to_owned(),
                ))
            }
            _ => None,
        }
    }

    pub(super) fn delegated_mutation_not_attempted(error: Self) -> Self {
        match error {
            Self::SubprocessNotStarted { .. } | Self::DelegatedMutationNotAttempted { .. } => error,
            other => Self::DelegatedMutationNotAttempted {
                message: other.to_string(),
            },
        }
    }
}

fn cloudflare_guidance(
    error: &cfctl_cloudflare::CloudflareError,
) -> Option<(&'static str, String)> {
    use cfctl_cloudflare::CloudflareError as E;
    let (code, step): (&'static str, &str) = match error {
        E::MissingSelector(_)
        | E::MissingHeaderSelector(_)
        | E::InvalidSelector(_)
        | E::InvalidSelectorObject
        | E::InvalidSelectorSchema { .. } => (
            "CFCTL_REQUEST_CONTRACT",
            "Run `cfctl guide <capability-id> --json` for the required selectors, then re-run `cfctl call` with each `--selector name=value`.",
        ),
        E::UndeclaredSelector(_) | E::InvalidQueryObject | E::UndeclaredQuerySelector(_) => (
            "CFCTL_REQUEST_CONTRACT",
            "Run `cfctl catalog show <capability-id> --json` to see the declared selectors and query controls, then drop or rename the undeclared input.",
        ),
        E::MissingQuerySelector(_)
        | E::InvalidQuerySelector { .. }
        | E::InvalidQuerySelectorSchema { .. }
        | E::UnsupportedQuerySerialization { .. } => (
            "CFCTL_REQUEST_CONTRACT",
            "Run `cfctl guide <capability-id>` and add each required `--query name=value`.",
        ),
        E::MissingRequestBody(_) | E::InvalidRequestBody(_) => (
            "CFCTL_REQUEST_CONTRACT",
            "Run `cfctl guide <capability-id>` for the body schema, then pass `--body-json '{…}'` (or `--body-stdin`).",
        ),
        E::ApprovedPlanRequired(_) => (
            "CFCTL_PLAN_REQUIRED",
            "This capability mutates state: draft, approve, then run. `cfctl call <capability-id> …` prints an operation id; then `cfctl plans approve <operation-id> --yes` and `cfctl plans run <operation-id>`.",
        ),
        E::CatalogDrift { .. } => (
            "CFCTL_CATALOG_DRIFT",
            "The catalog moved since the plan was drafted. Run `cfctl catalog sync`, then re-draft with `cfctl call <capability-id> …`.",
        ),
        E::Plan(core) => return core_guidance(core),
        _ => return None,
    };
    Some((code, step.to_owned()))
}

fn core_guidance(error: &cfctl_core::CoreError) -> Option<(&'static str, String)> {
    use cfctl_core::CoreError as E;
    const CODE: &str = "CFCTL_PLAN_LIFECYCLE";
    let step = match error {
        E::ExplicitApprovalRequired => {
            "Re-run with the explicit approval flag: `cfctl plans approve <operation-id> --yes`."
                .to_owned()
        }
        E::CostCeilingRequired(operation_id) => format!(
            "This plan needs an explicit cost ceiling: `cfctl plans approve {operation_id} --yes --max-cost USD:<amount>`."
        ),
        E::CostCeilingTooLow {
            operation_id,
            required_currency,
            required_amount,
        } => format!(
            "Raise the ceiling to at least the declared maximum: `cfctl plans approve {operation_id} --yes --max-cost {required_currency}:{required_amount}`."
        ),
        E::InvalidCostCeiling { .. } => {
            "Format the ceiling as CURRENCY:AMOUNT, for example `--max-cost USD:5`.".to_owned()
        }
        E::InvalidPlanState {
            operation_id,
            actual,
            expected,
        } => plan_state_next_step(operation_id, *actual, expected),
        E::PlanExpired { .. } => {
            "The plan expired. Re-draft with `cfctl call <capability-id> …`, then approve and run promptly."
                .to_owned()
        }
        E::PlanDrifted(_) => {
            "Approval no longer matches the plan content. Re-draft and re-approve: `cfctl call <capability-id> …`."
                .to_owned()
        }
        E::InvalidTransactionJournal { operation_id, .. } => {
            format!("Reconcile the plan's journal: `cfctl plans rectify {operation_id}`.")
        }
        _ => return None,
    };
    Some((CODE, step))
}

/// Recovery guidance for a rejected plan transition. Keys on the plan's ACTUAL
/// state — not the `expected` string — so a completed plan is never told to
/// re-approve/re-run, and a genuine run-before-approve is told to approve.
pub(super) fn plan_state_next_step(
    operation_id: &str,
    actual: cfctl_core::PlanStatus,
    expected: &str,
) -> String {
    use cfctl_core::PlanStatus as S;
    match actual {
        S::Consumed | S::Running | S::Verified => format!(
            "This plan already ran (state: {}); do not re-approve or re-run it. Inspect `cfctl plans status {operation_id}`, or draft a new plan with `cfctl call <capability-id> …` to repeat the change.",
            plan_status_label(actual)
        ),
        S::Failed | S::RectificationRequired => {
            format!("The plan did not complete and needs recovery: `cfctl plans rectify {operation_id}`.")
        }
        S::Rectified => {
            format!("The plan was already rectified; inspect `cfctl plans status {operation_id}`.")
        }
        S::Expired => {
            "The plan expired. Re-draft with `cfctl call <capability-id> …`, then approve and run promptly."
                .to_owned()
        }
        S::Cancelled => {
            "The plan was cancelled and its authority retired. If the change is still wanted, draft a new plan with `cfctl call <capability-id> …`."
                .to_owned()
        }
        S::Approved => {
            format!("The plan is already approved; run it: `cfctl plans run {operation_id}`.")
        }
        S::Draft => {
            if expected.contains("unchanged") || expected.contains("hash") {
                "The plan changed since it was drafted. Re-draft and re-approve: `cfctl call <capability-id> …`."
                    .to_owned()
            } else if expected.contains("unapproved") {
                format!(
                    "This draft is consumed under a standing policy, not approved by hand. Inspect it with `cfctl plans status {operation_id}`."
                )
            } else {
                format!(
                    "Approval is required before running. Approve it: `cfctl plans approve {operation_id} --yes`, then `cfctl plans run {operation_id}`."
                )
            }
        }
    }
}

pub(super) fn plan_status_label(status: cfctl_core::PlanStatus) -> &'static str {
    use cfctl_core::PlanStatus as S;
    match status {
        S::Draft => "draft",
        S::Approved => "approved",
        S::Running => "running",
        S::Consumed => "consumed",
        S::Verified => "verified",
        S::Failed => "failed",
        S::RectificationRequired => "rectification_required",
        S::Rectified => "rectified",
        S::Expired => "expired",
        S::Cancelled => "cancelled",
    }
}

fn storage_guidance(error: &cfctl_storage::StorageError) -> Option<(&'static str, String)> {
    use cfctl_storage::StorageError as E;
    let (code, step) = match error {
        E::PlanNotFound(id) => (
            "CFCTL_PLAN_LIFECYCLE",
            format!(
                "No plan with that id. Confirm it with `cfctl plans show {id}`; the operation id is printed by the `cfctl call` that drafted the plan."
            ),
        ),
        E::PlanLocked(id) => (
            "CFCTL_PLAN_LIFECYCLE",
            format!(
                "Another `cfctl plans` run holds the lock. Check `cfctl plans status {id}` and retry once it finishes."
            ),
        ),
        E::InvalidPlanId(_) | E::InvalidAuthorityId(_) => (
            "CFCTL_PLAN_LIFECYCLE",
            "Pass the operation id exactly as printed by `cfctl call` (a lowercase hyphenated UUID)."
                .to_owned(),
        ),
        E::WriteDurabilityUnknown { path, .. } if evidence_durability_path(path) => (
            "CFCTL_EVIDENCE_DURABILITY",
            "The exact evidence entry is visible, but its containing-directory durability is unconfirmed. Do not blindly replay the write. Reconcile the exact body, descriptor, or proof through its owning evidence path; success requires exact authentication and byte equality followed by a successful held-directory sync. Temporary-alias cleanup is a separate recovery condition."
                .to_owned(),
        ),
        E::WriteDurabilityUnknown { .. } => (
            "CFCTL_PLAN_LIFECYCLE",
            "The write is not durably confirmed. Reload with `cfctl plans status <operation-id>` before retrying."
                .to_owned(),
        ),
        E::CapabilityPublicationCleanupFailed { .. } => (
            "CFCTL_EVIDENCE_PUBLICATION_CLEANUP",
            "The final evidence document was published, but its temporary hard-link alias remains. Do not replay the write; inspect and resolve the exact reported alias before evidence lifecycle scans continue."
                .to_owned(),
        ),
        E::InvalidPlan(core) => return core_guidance(core),
        _ => return None,
    };
    Some((code, step))
}

fn evidence_durability_path(path: &str) -> bool {
    let path = std::path::Path::new(path);
    if path.file_name().and_then(std::ffi::OsStr::to_str) == Some("evidence-root-v1.json") {
        return true;
    }
    matches!(
        path.parent()
            .and_then(std::path::Path::file_name)
            .and_then(std::ffi::OsStr::to_str),
        Some("evidence" | "evidence-descriptors" | "evidence-index")
    )
}

fn auth_guidance(error: &cfctl_auth::AuthError) -> Option<(&'static str, String)> {
    use cfctl_auth::AuthError as E;
    const CODE: &str = "CFCTL_AUTH";
    let step = match error {
        E::CredentialUnavailable { profile_id, .. } => {
            return Some((
                "CFCTL_CREDENTIAL_UNAVAILABLE",
                format!(
                    "Re-import the credential for the selected profile `{profile_id}`. If the only valid copy is intentionally in Keychain, run `cfctl auth repair-keychain-access {profile_id}` and review its warning before continuing."
                ),
            ));
        }
        E::MissingCredential(_) => {
            "The profile has no stored credential. Re-import it: `printf '%s' \"$TOKEN\" | cfctl auth import-api-token --account <account-id> --stdin`."
                .to_owned()
        }
        E::NoAccounts | E::AmbiguousAccount { .. } | E::AccountNotFound(_) => {
            "Pass `--account <account-id>` explicitly (list available accounts with `cfctl auth status --json`)."
                .to_owned()
        }
        E::UnsupportedLegacyWranglerSession(id) => format!(
            "Remove the legacy profile and re-authenticate: `cfctl auth logout {id}` then `cfctl auth login --profile {id}`."
        ),
        E::EvidenceKeyLifecycle(cfctl_auth::EvidenceKeyLifecycleError::Unchanged { .. }) => {
            return Some((
                "CFCTL_EVIDENCE_KEY_UNCHANGED",
                "Run `cfctl auth evidence-key status --json`; exact registry readback proved the attempted mutation did not cross, so retry only after confirming the same lifecycle intent."
                    .to_owned(),
            ));
        }
        E::EvidenceKeyLifecycle(cfctl_auth::EvidenceKeyLifecycleError::Indeterminate {
            action,
            ..
        }) => {
            let next_step = if action == "malformed-registry recovery" {
                "Do not initialize or create a replacement plan. Preserve private quarantine, inspect the same opaque plan with `cfctl auth evidence-key recover-plan status <plan-id> --json`, reconcile the marker readback, and resume only that same plan forward with `cfctl auth evidence-key recover <plan-id> --yes --json`."
            } else {
                "Do not replay rotate or retire. Run `cfctl auth evidence-key status --json` and reconcile the exact platform registry before any further evidence-key mutation."
            };
            return Some((
                "CFCTL_EVIDENCE_KEY_INDETERMINATE",
                next_step.to_owned(),
            ));
        }
        E::SecretStore(_) => {
            "The secret backend is unavailable. Run `cfctl doctor --json` to inspect the credential store."
                .to_owned()
        }
        _ => return None,
    };
    Some((CODE, step))
}

/// Map a non-2xx live Cloudflare read status to a stable code and a specific
/// next command. Authorization failures point at the token scope; input
/// failures point at the selector/zone contract; the rest fall back to doctor.
pub(super) fn live_read_failure_guidance(status: u16) -> (&'static str, String) {
    match status {
        401 | 403 => (
            "CFCTL_LIVE_UNAUTHORIZED",
            "The token lacks scope for this read. Confirm its permissions with `cfctl keys permissions --json`, or select a scoped profile with `--profile <id>`."
                .to_owned(),
        ),
        400 | 404 | 422 => (
            "CFCTL_LIVE_BAD_REQUEST",
            "Cloudflare rejected the inputs. Run `cfctl guide <capability-id>` to check required selectors — zone selectors need the 32-hex zone id, not a domain (resolve it with a `/zones` read filtered by `--query name=<domain>`)."
                .to_owned(),
        ),
        429 => (
            "CFCTL_LIVE_RATE_LIMITED",
            "Cloudflare rate-limited the request. Wait and retry the same `cfctl call`.".to_owned(),
        ),
        500..=599 => (
            "CFCTL_LIVE_UPSTREAM",
            "Cloudflare reported a server-side error. Retry shortly; if it persists, run `cfctl doctor --json`."
                .to_owned(),
        ),
        _ => (
            "CFCTL_LIVE_ERROR",
            "The live read failed. Inspect the returned Cloudflare errors and run `cfctl doctor --json`."
                .to_owned(),
        ),
    }
}

pub(super) fn live_read_availability(
    capability: &CapabilityV1,
    response: &CloudflareResponseV1,
) -> Value {
    let permission_owner =
        if capability.path.starts_with("/user") || capability.account_scope == "user" {
            "user_owned"
        } else {
            "account_owned"
        };
    let analytics_rows = capability.analytics_query.as_ref().and_then(|_| {
        response
            .result_info
            .as_ref()
            .and_then(|info| info.pointer("/output/rows"))
            .and_then(Value::as_u64)
    });
    let (state, data_state, distinction_proven, next_action) = if email_routing_contract_diagnostic(
        capability, response,
    )
    .is_some()
    {
        (
            "response_contract_rejected",
            "not_observed",
            true,
            "Inspect the bounded diagnostic code and update the cfctl-owned Email Routing projection contract before retrying; never consume or expose the raw provider response.",
        )
    } else if response.success {
        if analytics_rows == Some(0) {
            (
                "available",
                "no_data_in_bounded_query_window",
                true,
                "Widen the governed time window within the capability limit or verify dataset freshness and retention; cfctl does not reinterpret an empty result as an authorization failure.",
            )
        } else {
            (
                "available",
                "data_returned_or_not_applicable",
                true,
                "Inspect the content-addressed live-read receipt and any freshness, sampling, pagination, or truncation metadata.",
            )
        }
    } else if capability.entitlement.available == Some(false) {
        (
            "unavailable_current_plan",
            "not_observed",
            true,
            "Review the capability entitlement source and use an eligible account or plan; do not retry as a permission workaround.",
        )
    } else if matches!(response.status, 401 | 403) {
        (
            "authorization_or_entitlement_unresolved",
            "not_observed",
            false,
            "Compare the active token against required_permissions. If those permissions are present, inspect the capability entitlement source or a governed product-specific entitlement read; cfctl does not guess which boundary Cloudflare rejected.",
        )
    } else if response.status == 404 {
        (
            "resource_or_configuration_absent",
            "not_observed",
            true,
            "Verify the exact account, zone, and resource selectors. A 404 is not treated as an empty analytics result.",
        )
    } else {
        (
            "upstream_error",
            "not_observed",
            true,
            "Inspect the redacted Cloudflare errors and retry only when the status-specific guidance permits it.",
        )
    };
    json!({
        "schema_version": 1,
        "state": state,
        "data_state": data_state,
        "authorization_entitlement_distinction_proven": distinction_proven,
        "permission_owner": permission_owner,
        "required_permissions": &capability.permissions,
        "entitlement": &capability.entitlement,
        "freshness": capability.analytics_query.as_ref().and_then(|query| query.freshness.as_deref()),
        "sampling": capability.analytics_query.as_ref().and_then(|query| query.sampling.as_deref()),
        "next_action": next_action,
    })
}

pub(super) fn email_routing_contract_diagnostic<'a>(
    capability: &CapabilityV1,
    response: &'a CloudflareResponseV1,
) -> Option<&'a Value> {
    (cfctl_core::is_email_routing_rules_list_capability(capability)
        // The adapter also uses this redacted diagnostic shape to suppress a
        // failed provider page. A non-2xx status is provider rejection, not
        // projection drift, so status-specific live-read guidance must win.
        && (200..300).contains(&response.status)
        && response
            .result
            .get("schema_version")
            .and_then(Value::as_u64)
            == Some(1)
        && response.result.get("complete").and_then(Value::as_bool) == Some(false))
    .then(|| response.result.get("diagnostic"))
    .flatten()
    .filter(|diagnostic| {
        diagnostic.get("schema_version").and_then(Value::as_u64) == Some(1)
            && diagnostic.get("code").and_then(Value::as_str).is_some()
            && diagnostic
                .get("component")
                .and_then(Value::as_str)
                .is_some()
    })
}

pub(super) fn live_read_failure_guidance_for_response(
    capability: &CapabilityV1,
    response: &CloudflareResponseV1,
) -> (&'static str, String) {
    if email_routing_contract_diagnostic(capability, response).is_some() {
        return (
            "CFCTL_RESPONSE_CONTRACT_MISMATCH",
            "Inspect only the bounded diagnostic code, update the cfctl-owned response projection with reserved fixtures, and repeat the exact read; do not expose or consume raw provider values."
                .to_owned(),
        );
    }
    live_read_failure_guidance(response.status)
}
