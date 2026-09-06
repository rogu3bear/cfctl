use cfctl_auth::{AuthCredential, ProfileMetadata};
use cfctl_catalog::CatalogSnapshot;
use cfctl_cloudflare::CallInput;
use cfctl_core::{
    CapabilityV1, ErrorV1, EvidenceClass, EvidenceV1, ResultEnvelopeV2, VerificationState,
};
use cfctl_storage::StateStore;
use serde_json::Value;

use super::{
    call_input::resolve_account_id,
    credential_resolution::{fresh_credential, platform_secrets},
    governed_cli::run_delegated_cli,
    prelude::{CliError, Path, Result},
    read_execution::{ExecutedRead, credential_generation_for_read},
    workspace_d1_evidence, workspace_d1_reply_admission, workspace_reply_subdomain_ingress,
};
use crate::profiles::ProfilesConfig;

pub(super) struct Request<'a> {
    pub(super) store: &'a StateStore,
    pub(super) catalog: &'a CatalogSnapshot,
    pub(super) capability: &'a CapabilityV1,
    pub(super) input: &'a CallInput,
    pub(super) requested_profile: Option<&'a str>,
    pub(super) requested_account: Option<&'a str>,
    pub(super) reply_admission_source: Option<&'a Path>,
}

struct AuthorityContext {
    profile: ProfileMetadata,
    account_id: Option<String>,
    credential: AuthCredential,
    credential_generation_id: String,
}

impl AuthorityContext {
    async fn resolve(request: &Request<'_>) -> Result<Self> {
        let profiles = ProfilesConfig::load(request.store)?;
        let profile = profiles.selected(request.requested_profile)?.clone();
        let credential_generation_id = credential_generation_for_read(&profile)?;
        let account_id = resolve_account_id(
            request.store,
            &profile,
            request.requested_account,
            request.input,
        )?;
        let credential = fresh_credential(&profile, &platform_secrets(request.store)).await?;
        Ok(Self {
            profile,
            account_id,
            credential,
            credential_generation_id,
        })
    }

    fn exact_account(&self, missing_message: &str) -> Result<&str> {
        self.account_id
            .as_deref()
            .ok_or_else(|| CliError::Input(missing_message.to_owned()))
    }
}

#[derive(Clone, Copy)]
enum ReadKind {
    WorkspaceReplySubdomainIngress,
    WorkspaceD1ReplyAdmission,
    WorkspaceD1Evidence,
    Generic,
}

impl ReadKind {
    fn classify(capability: &CapabilityV1) -> Self {
        if capability.workspace_reply_subdomain_ingress.is_some() {
            Self::WorkspaceReplySubdomainIngress
        } else if capability
            .workspace_d1_reply_admission
            .as_ref()
            .is_some_and(|contract| contract.operation_kind == "read")
        {
            Self::WorkspaceD1ReplyAdmission
        } else if capability.workspace_d1_evidence.is_some() {
            Self::WorkspaceD1Evidence
        } else {
            Self::Generic
        }
    }

    fn receipt_is_complete(self, receipt: &Value) -> bool {
        match self {
            Self::WorkspaceReplySubdomainIngress => {
                workspace_reply_subdomain_ingress::receipt_is_complete(receipt)
            }
            Self::WorkspaceD1ReplyAdmission => {
                workspace_d1_reply_admission::read_receipt_is_complete(receipt)
            }
            Self::WorkspaceD1Evidence => workspace_d1_evidence::receipt_is_complete(receipt),
            Self::Generic => false,
        }
    }

    fn apply_verification(self, envelope: &mut ResultEnvelopeV2, receipt_is_complete: bool) {
        match self {
            Self::WorkspaceReplySubdomainIngress => {
                set_workspace_reply_subdomain_ingress_verification(envelope, receipt_is_complete);
            }
            Self::WorkspaceD1ReplyAdmission => {
                set_workspace_reply_admission_read_verification(envelope, receipt_is_complete);
            }
            Self::WorkspaceD1Evidence => {
                set_workspace_d1_evidence_verification(envelope, receipt_is_complete);
            }
            Self::Generic => {}
        }
    }
}

enum ReadOutcome {
    Receipt(Value),
    Final(Box<ExecutedRead>),
}

struct ExecutionContext<'a> {
    request: Request<'a>,
    authority: AuthorityContext,
    kind: ReadKind,
}

impl ExecutionContext<'_> {
    async fn read(&self) -> Result<ReadOutcome> {
        let request = &self.request;
        let authority = &self.authority;
        let receipt = match self.kind {
            ReadKind::WorkspaceReplySubdomainIngress => {
                let account_id = authority.exact_account(
                    "workspace reply-subdomain ingress read requires an exact account",
                )?;
                workspace_reply_subdomain_ingress::read(
                    request.store,
                    request.catalog,
                    request.capability,
                    request.input,
                    &authority.credential,
                    &authority.profile,
                    account_id,
                    request.requested_account,
                    &authority.credential_generation_id,
                )
                .await?
            }
            ReadKind::WorkspaceD1ReplyAdmission => {
                let account_id = authority
                    .exact_account("workspace reply-admission read requires an exact account")?;
                let source = request.reply_admission_source.ok_or_else(|| {
                    CliError::Input(
                        "workspace reply-admission read requires one private source file"
                            .to_owned(),
                    )
                })?;
                workspace_d1_reply_admission::read(
                    request.store,
                    request.capability,
                    request.input,
                    &authority.credential,
                    &authority.profile,
                    account_id,
                    source,
                )
                .await?
            }
            ReadKind::WorkspaceD1Evidence => {
                let account_id =
                    authority.exact_account("workspace D1 evidence requires an exact account")?;
                match workspace_d1_evidence::execute(
                    request.store,
                    request.capability,
                    request.input,
                    &authority.credential,
                    account_id,
                )
                .await
                {
                    Ok(receipt) => receipt,
                    Err(failure) => {
                        return Ok(ReadOutcome::Final(Box::new(
                            self.d1_failure(account_id, &failure)?,
                        )));
                    }
                }
            }
            ReadKind::Generic => {
                run_delegated_cli(
                    request.capability,
                    request.input,
                    &authority.credential,
                    authority.account_id.as_deref(),
                    &request.store.paths().cache_dir,
                    None,
                    None,
                )
                .await?
            }
        };
        Ok(ReadOutcome::Receipt(receipt))
    }

    fn d1_failure(
        &self,
        account_id: &str,
        failure: &workspace_d1_evidence::WorkspaceD1EvidenceFailure,
    ) -> Result<ExecutedRead> {
        let receipt = failure.receipt();
        let evidence = if failure.boundary_crossed() {
            Some(
                self.request
                    .store
                    .write_observation_evidence(EvidenceClass::LiveRead, &receipt)?,
            )
        } else {
            None
        };
        let mut envelope = envelope(
            &self.request.catalog.schema_hash,
            &self.request.capability.id,
            &self.authority.profile.id,
            Some(account_id.to_owned()),
            receipt,
            evidence,
        );
        envelope.verification.state = VerificationState::Failed;
        envelope.verification.basis = Some(
            "workspace D1 evidence failed closed without retaining provider rows or message bodies"
                .to_owned(),
        );
        Ok(ExecutedRead {
            envelope,
            credential_generation_id: Some(self.authority.credential_generation_id.clone()),
        })
    }

    fn finish(self, receipt: Value) -> Result<ExecutedRead> {
        let receipt_is_complete = self.kind.receipt_is_complete(&receipt);
        let evidence = self
            .request
            .store
            .write_observation_evidence(EvidenceClass::LiveRead, &receipt)?;
        let mut envelope = envelope(
            &self.request.catalog.schema_hash,
            &self.request.capability.id,
            &self.authority.profile.id,
            self.authority.account_id,
            receipt,
            Some(evidence),
        );
        self.kind
            .apply_verification(&mut envelope, receipt_is_complete);
        Ok(ExecutedRead {
            envelope,
            credential_generation_id: Some(self.authority.credential_generation_id),
        })
    }
}

pub(super) async fn execute(request: Request<'_>) -> Result<ExecutedRead> {
    let kind = ReadKind::classify(request.capability);
    let authority = AuthorityContext::resolve(&request).await?;
    let context = ExecutionContext {
        request,
        authority,
        kind,
    };
    match context.read().await? {
        ReadOutcome::Receipt(receipt) => context.finish(receipt),
        ReadOutcome::Final(executed) => Ok(*executed),
    }
}

pub(super) fn envelope(
    catalog_hash: &str,
    capability_id: &str,
    profile_id: &str,
    account_id: Option<String>,
    receipt: Value,
    evidence: Option<EvidenceV1>,
) -> ResultEnvelopeV2 {
    let success = receipt
        .get("success")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let workspace_failure = workspace_d1_evidence_failure(&receipt);
    let mut envelope = ResultEnvelopeV2::success("call", receipt);
    if let Some(evidence) = evidence {
        envelope = envelope.with_evidence(evidence);
    }
    envelope.ok = success;
    envelope.performed = workspace_failure
        .as_ref()
        .is_none_or(|failure| failure.boundary_crossed);
    envelope.capability_id = Some(capability_id.to_owned());
    envelope.profile_id = Some(profile_id.to_owned());
    envelope.account_id = account_id;
    if let Some(failure) = workspace_failure {
        envelope.verification.state = VerificationState::Failed;
        envelope.verification.basis = Some(format!(
            "workspace D1 evidence failed closed at `{}` without retaining provider output",
            failure.stage
        ));
        let next_step = if failure.boundary_crossed {
            "Do not replay or infer D1 readiness from lower planes; preserve this receipt, repair the exact provider-read or projection blocker, then run one fresh coherent transaction."
        } else {
            "Repair the exact workspace D1 evidence preflight blocker, re-admit the bound cfctl build, then run one fresh coherent transaction; do not bypass cfctl with Wrangler."
        };
        envelope.error = Some(ErrorV1 {
            code: failure.code.clone(),
            message: format!(
                "workspace D1 evidence failed at governed stage `{}`; provider output was not retained",
                failure.stage
            ),
            next_step: Some(next_step.to_owned()),
        });
    } else {
        envelope.verification.state = VerificationState::NotApplicable;
        envelope.verification.basis = Some(format!(
            "governed CLI read pinned to catalog {catalog_hash}"
        ));
    }
    envelope
}

pub(super) fn set_workspace_d1_evidence_verification(
    envelope: &mut ResultEnvelopeV2,
    receipt_is_complete: bool,
) {
    let inbound_acceptance = envelope.result.get("adapter").and_then(Value::as_str)
        == Some("workspace_inbound_acceptance_v1");
    envelope.verification.state = if receipt_is_complete {
        VerificationState::Passed
    } else {
        VerificationState::Failed
    };
    envelope.verification.basis = Some(if receipt_is_complete && inbound_acceptance {
        "clean-repository fixed D1 projection reduced one deterministic delivery fingerprint to exactly one accepted body-free inbound, relay, and thread binding without retaining provider rows"
            .to_owned()
    } else if receipt_is_complete {
        "clean-repository fixed D1 projection reduced to MaildeskD1EvidenceV1 plus complete bounded body-free MaildeskD1RouteHealthEvidenceV2 without retaining provider rows".to_owned()
    } else if inbound_acceptance {
        "workspace D1 inbound-acceptance receipt did not prove exactly one fully provider-accepted binding for the selected delivery fingerprint, route, and policy".to_owned()
    } else {
        "workspace D1 evidence receipt did not prove a coherent V1 aggregate plus complete bounded body-free V2 route-health projection"
            .to_owned()
    });
}

fn set_workspace_reply_subdomain_ingress_verification(
    envelope: &mut ResultEnvelopeV2,
    receipt_is_complete: bool,
) {
    envelope.verification.state = if receipt_is_complete {
        VerificationState::Passed
    } else {
        VerificationState::Failed
    };
    envelope.verification.basis = Some(if receipt_is_complete {
        "the authoritative parent zone, exact subdomain DNS settings, and one exact account-inventory all-matcher Worker rule were reduced to the closed body-free Maildesk ingress result"
            .to_owned()
    } else {
        "reply-subdomain ingress did not produce one complete body-free parent-zone, exact subdomain-DNS, and account-rule projection"
            .to_owned()
    });
    if !receipt_is_complete {
        envelope.error = Some(ErrorV1 {
            code: "CFCTL_WORKSPACE_REPLY_SUBDOMAIN_INGRESS_READ_FAILED".to_owned(),
            message: "the governed reply-subdomain ingress read did not complete".to_owned(),
            next_step: Some(
                "Preserve the body-free failure receipt and reconcile the exact parent-zone, subdomain DNS, or complete account-rule inventory blocker; do not infer subdomain routing from the parent-zone catch-all."
                    .to_owned(),
            ),
        });
    }
}

fn set_workspace_reply_admission_read_verification(
    envelope: &mut ResultEnvelopeV2,
    receipt_is_complete: bool,
) {
    envelope.verification.state = if receipt_is_complete {
        VerificationState::Passed
    } else {
        VerificationState::Failed
    };
    envelope.verification.basis = Some(if receipt_is_complete {
        "exactly one active reply admission matched the compiler-owned transaction, activation record, identity projection, and activation operation without retaining provider rows"
            .to_owned()
    } else {
        "reply-admission read did not prove one exact active body-free record; later mail planes remain blocked"
            .to_owned()
    });
    if !receipt_is_complete {
        envelope.error = Some(ErrorV1 {
            code: "CFCTL_WORKSPACE_D1_REPLY_ADMISSION_READ_FAILED".to_owned(),
            message: "the governed reply-admission read returned no exact active match".to_owned(),
            next_step: Some(
                "Preserve this body-free receipt and reconcile the exact activation transaction; do not retry through caller SQL or infer readiness from the plan."
                    .to_owned(),
            ),
        });
    }
}

struct WorkspaceD1EvidenceFailureReceipt {
    code: String,
    stage: String,
    boundary_crossed: bool,
}

fn workspace_d1_evidence_failure(receipt: &Value) -> Option<WorkspaceD1EvidenceFailureReceipt> {
    if receipt.get("adapter").and_then(Value::as_str) != Some("workspace_d1_evidence_v1")
        || receipt.get("success").and_then(Value::as_bool) != Some(false)
        || receipt
            .get("provider_output_retained")
            .and_then(Value::as_bool)
            != Some(false)
        || receipt.get("body_returned").and_then(Value::as_bool) != Some(false)
    {
        return None;
    }
    let code = receipt.get("failure_code").and_then(Value::as_str)?;
    if !matches!(
        code,
        "CFCTL_WORKSPACE_D1_EVIDENCE_PREFLIGHT_FAILED"
            | "CFCTL_WORKSPACE_D1_EVIDENCE_WRANGLER_VERSION_FAILED"
            | "CFCTL_WORKSPACE_D1_EVIDENCE_PROVIDER_READ_FAILED"
            | "CFCTL_WORKSPACE_D1_EVIDENCE_PROJECTION_FAILED"
    ) {
        return None;
    }
    let stage = receipt.get("failure_stage").and_then(Value::as_str)?;
    let boundary_crossed = receipt.get("boundary_crossed").and_then(Value::as_bool)?;
    Some(WorkspaceD1EvidenceFailureReceipt {
        code: code.to_owned(),
        stage: stage.to_owned(),
        boundary_crossed,
    })
}
