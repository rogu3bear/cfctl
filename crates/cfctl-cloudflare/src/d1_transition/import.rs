//! Native D1 file-import transport preparation. No catalog/CLI routing is registered.
//! Reuses the existing presigned-upload, `ETag` and nested import response validators.
use cfctl_auth::AuthCredential;
use cfctl_core::{
    CapabilityV1, PlanStatus, PlanV2, TransactionStageV1,
    workspace_d1::transition::{
        canonical_digest,
        execution::{Checkpoint, Stage},
        proofs::{
            Identity, PollContinuation, QualificationTarget, TRANSPORT, TRANSPORT_RECEIPT_KIND,
            TransportReceipt, WriterTarget,
        },
    },
};
use md5::{Digest, Md5};
use serde_json::{Value, json};
use sha2::Sha256;

use crate::{
    CallInput, Executor,
    d1_import::{
        D1ImportIngestOutcome, D1ImportPollOutcome, bounded_d1_import_upload,
        classify_d1_import_ingest_response, classify_d1_import_init_response,
        classify_d1_import_poll_response, validated_d1_import_upload_etag,
    },
};

use super::{Failure, Terminal, execute_once};
mod private_error;
pub use private_error::PrivateImportErrorV1;

/// Constructible only from a consumed, boundary-attempted, exact approved plan.
pub struct ValidatedImport {
    checkpoint: Checkpoint,
    database_id: String,
    execution_length: usize,
    continuation: Option<PollContinuation>,
}

/// Poll-only authority for one privately retained bookmark and ambiguous parent.
pub struct ValidatedPoll {
    binding: ValidatedImport,
    bookmark: String,
}

impl ValidatedPoll {
    pub fn from_consumed_plan(
        plan: &PlanV2,
        original: &PlanV2,
        parent: &Checkpoint,
        bookmark: &str,
    ) -> Result<Self, &'static str> {
        plan.validate().map_err(|_| "invalid poll plan")?;
        original
            .validate()
            .map_err(|_| "invalid poll parent plan")?;
        parent.validate()?;
        let database = plan
            .plan
            .input
            .pointer("/selectors/database_id")
            .and_then(Value::as_str)
            .ok_or("poll target missing")?;
        let bookmark_hash = format!(
            "sha256:{}",
            hex::encode(Sha256::digest(bookmark.as_bytes()))
        );
        let target = json!({"parent_operation_id":parent.operation_id,"parent_plan_hash":parent.plan_hash,
            "checkpoint_sha256":cfctl_core::hash_value(&serde_json::to_value(parent).map_err(|_|"invalid parent")?).map_err(|_|"invalid parent")?,
            "bookmark_sha256":bookmark_hash,"database_id":database,"identity":parent.identity});
        if plan.plan.status != PlanStatus::Running
            || plan.plan.transaction_stage != TransactionStageV1::BoundaryAttemptPersisted
            || plan.plan.capability.path != "workspace:d1-transition-poll-v1"
            || plan
                .plan
                .approval
                .as_ref()
                .map(|approval| approval.approved_content_hash.as_str())
                != Some(plan.plan.content_hash.as_str())
            || plan.plan.account_id != parent.identity.account_id
            || plan.plan.profile_id != original.plan.profile_id
            || plan.plan.catalog_hash != original.plan.catalog_hash
            || plan.pins.catalog_hash != original.pins.catalog_hash
            || plan.pins.build_identity_hash != original.pins.build_identity_hash
            || plan.pins.credential_generation_id != original.pins.credential_generation_id
            || original.plan.operation_id != parent.operation_id
            || original.plan.content_hash != parent.plan_hash
            || original.plan.account_id != parent.identity.account_id
            || original
                .plan
                .input
                .pointer("/selectors/database_id")
                .and_then(Value::as_str)
                != Some(database)
            || !matches!(
                original.plan.status,
                PlanStatus::Running | PlanStatus::RectificationRequired | PlanStatus::Consumed
            )
            || !matches!(
                original.plan.capability.path.as_str(),
                "workspace:d1-transition-envelope-v3" | "workspace:d1-transition-qualification-v1"
            )
            || plan
                .plan
                .input
                .pointer("/selectors/account_id")
                .and_then(Value::as_str)
                != Some(parent.identity.account_id.as_str())
            || !matches!(
                parent.stage,
                Stage::Uncertain | Stage::DispatchIntent | Stage::AwaitingTerminal
            )
            || bookmark.is_empty()
            || bookmark.len() > 4096
            || uuid::Uuid::parse_str(database).is_err()
            || plan
                .plan
                .targets
                .pointer("/adapter/workspace_d1_transition_poll")
                != Some(&target)
        {
            return Err(
                "poll requires exact consumed approval, private bookmark and ambiguous parent",
            );
        }
        Ok(Self {
            binding: ValidatedImport {
                checkpoint: parent.clone(),
                database_id: database.into(),
                execution_length: 0,
                continuation: Some(PollContinuation {
                    operation_id: plan.plan.operation_id.clone(),
                    plan_hash: plan.plan.content_hash.clone(),
                    parent_checkpoint_sha256: cfctl_core::hash_value(
                        &serde_json::to_value(parent).map_err(|_| "invalid parent")?,
                    )
                    .map_err(|_| "invalid parent")?,
                    bookmark_sha256: bookmark_hash,
                }),
            },
            bookmark: bookmark.into(),
        })
    }
}

impl ValidatedImport {
    pub fn from_consumed_plan(
        plan: &PlanV2,
        checkpoint: &Checkpoint,
    ) -> Result<Self, &'static str> {
        plan.validate().map_err(|_| "invalid native import plan")?;
        checkpoint.validate()?;
        if plan.plan.status != PlanStatus::Running
            || plan.plan.transaction_stage != TransactionStageV1::BoundaryAttemptPersisted
            || plan.plan.operation_id != checkpoint.operation_id
            || plan.plan.content_hash != checkpoint.plan_hash
            || plan
                .plan
                .approval
                .as_ref()
                .map(|approval| approval.approved_content_hash.as_str())
                != Some(plan.plan.content_hash.as_str())
            || plan.plan.account_id != checkpoint.identity.account_id
            || checkpoint.stage != Stage::Prepared
        {
            return Err("native import requires the exact consumed approved boundary");
        }
        let database = plan
            .plan
            .input
            .pointer("/selectors/database_id")
            .and_then(Value::as_str)
            .ok_or("native import database missing")?;
        if plan
            .plan
            .input
            .pointer("/selectors/account_id")
            .and_then(Value::as_str)
            != Some(checkpoint.identity.account_id.as_str())
        {
            return Err("native import account selector differs");
        }
        let execution_length = if let Some(contract) = &plan.plan.capability.workspace_d1_migration
        {
            if Identity::from_contract(contract).map_err(|_| "native import source missing")?
                != checkpoint.identity
                || database != checkpoint.identity.database_id
                || plan.plan.capability.path != "workspace:d1-transition-envelope-v3"
            {
                return Err("native import source transition differs");
            }
            contract
                .transition
                .as_ref()
                .ok_or("native source missing")?
                .execution
                .execution_length
        } else {
            qualification_execution_length(plan, checkpoint, database)?
        };
        if uuid::Uuid::parse_str(database).is_err() {
            return Err("native import database invalid");
        }
        Ok(Self {
            checkpoint: checkpoint.clone(),
            database_id: database.into(),
            execution_length,
            continuation: None,
        })
    }
}

fn qualification_execution_length(
    plan: &PlanV2,
    checkpoint: &Checkpoint,
    database: &str,
) -> Result<usize, &'static str> {
    let writer = plan.plan.capability.path == "workspace:d1-transition-writer-v1";
    let target: QualificationTarget = if writer {
        let value = plan
            .plan
            .targets
            .pointer("/adapter/workspace_d1_transition_writer")
            .ok_or("writer target missing")?;
        serde_json::from_value::<WriterTarget>(value.clone())
            .map_err(|_| "writer target malformed")?
            .parent
    } else {
        let value = plan
            .plan
            .targets
            .pointer("/adapter/workspace_d1_transition_qualification")
            .ok_or("native qualification target missing")?;
        serde_json::from_value(value.clone())
            .map_err(|_| "native qualification target malformed")?
    };
    target.validate()?;
    let mut identity = target.identity.clone();
    let (digest, bytes) = if writer {
        let source = target
            .concurrent_source
            .as_ref()
            .ok_or("writer case source missing")?;
        (source.writer.sha256.clone(), source.writer_bytes)
    } else {
        (target.fixture_sha256.clone(), target.fixture_bytes)
    };
    identity.execution_sha256 = digest;
    if (!writer && plan.plan.capability.path != "workspace:d1-transition-qualification-v1")
        || database == identity.database_id
        || target.synthetic_database_id != database
        || identity != checkpoint.identity
    {
        return Err("native qualification isolation or fixture differs");
    }
    Ok(bytes)
}

/// No `Debug`/`Serialize`: the bookmark belongs only in a private resume sink.
pub struct Progress {
    pub operation_id: String,
    pub database_id: String,
    pub phase: &'static str,
    pub at_bookmark: Option<String>,
    pub terminal_bookmark: Option<String>,
    pub provider_error: Option<PrivateImportErrorV1>,
    pub terminal: Option<TransportReceipt>,
}

impl Executor {
    fn transition_transport(&self) -> Result<Self, ()> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .build()
            .map_err(|_| ())?;
        let mut transport = self.clone().with_max_retries(0);
        transport.client = client.clone();
        transport.upload_client = client;
        Ok(transport)
    }
    /// No init, upload or ingest path exists in this continuation.
    pub async fn poll_transition_import<S>(
        &self,
        authority: &ValidatedPoll,
        credential: &AuthCredential,
        mut persist: S,
    ) -> Terminal
    where
        S: FnMut(&Progress) -> Result<String, ()>,
    {
        let Ok(transport) = self.transition_transport() else {
            return Terminal::Uncertain;
        };
        match tokio::time::timeout(
            std::time::Duration::from_mins(10),
            transport.poll_transition(
                &authority.binding,
                &authority.bookmark,
                credential,
                &mut persist,
            ),
        )
        .await
        {
            Ok(Ok(terminal)) => terminal,
            _ => Terminal::Uncertain,
        }
    }
    /// Internal Rust API only. The native V3 CLI and catalog remain disabled.
    pub async fn execute_transition_import<P, S>(
        &self,
        binding: &ValidatedImport,
        execution: &[u8],
        credential: &AuthCredential,
        persist_checkpoint: P,
        mut persist_progress: S,
    ) -> Result<Checkpoint, Failure>
    where
        P: FnMut(&Checkpoint) -> Result<(), ()>,
        S: FnMut(&Progress) -> Result<String, ()>,
    {
        if execution.len() != binding.execution_length {
            return Err(Failure {
                durable: Box::new(binding.checkpoint.clone()),
                classification: "native_execution_length_differs",
            });
        }
        let transport = self.transition_transport().map_err(|()| Failure {
            durable: Box::new(binding.checkpoint.clone()),
            classification: "native_transport_unavailable",
        })?;
        execute_once(
            &binding.checkpoint,
            execution,
            persist_checkpoint,
            |bytes| async move {
                let run = transport.import_transition_bytes(
                    binding,
                    &bytes,
                    credential,
                    &mut persist_progress,
                );
                // A bounded observation window, not a claim about provider execution duration.
                match tokio::time::timeout(std::time::Duration::from_mins(10), run).await {
                    Ok(Ok(terminal)) => terminal,
                    _ => Terminal::Uncertain,
                }
            },
        )
        .await
    }

    async fn transition_import_request(
        &self,
        binding: &ValidatedImport,
        body: Value,
        credential: &AuthCredential,
    ) -> Result<crate::CloudflareResponseV1, ()> {
        let capability = CapabilityV1::new(
            "internal-v3-import-transport",
            "Unregistered native import transport",
            "POST",
            "/accounts/{account_id}/d1/database/{database_id}/import",
        );
        let input = CallInput {
            selectors: json!({"account_id":binding.checkpoint.identity.account_id,
            "database_id":binding.database_id}),
            query: json!({}),
            body: Some(body),
            ..CallInput::default()
        };
        let mut request = self
            .builder
            .build_unchecked(&capability, &input)
            .map_err(|_| ())?;
        request.timeout_seconds = 30;
        request.max_bytes = 65536;
        self.clone()
            .with_max_retries(0)
            .send(&request, credential)
            .await
            .map_err(|_| ())
    }

    async fn import_transition_bytes<S>(
        &self,
        binding: &ValidatedImport,
        bytes: &[u8],
        credential: &AuthCredential,
        persist: &mut S,
    ) -> Result<Terminal, ()>
    where
        S: FnMut(&Progress) -> Result<String, ()>,
    {
        let etag = hex::encode(Md5::digest(bytes));
        progress(binding, "init_intent", None, None, persist)?;
        let init = self
            .transition_import_request(binding, json!({"action":"init","etag":etag}), credential)
            .await?;
        let init = classify_d1_import_init_response(
            &init,
            &binding.checkpoint.identity.account_id,
            ".r2.cloudflarestorage.com",
        )
        .map_err(|_| ())?;
        progress(binding, "upload_intent", None, None, persist)?;
        let (status, headers) = bounded_d1_import_upload(
            &self.upload_client,
            init.upload_url,
            bytes.to_vec(),
            30,
            65536,
        )
        .await
        .map_err(|_| ())?;
        if !status.is_success() {
            return Err(());
        }
        validated_d1_import_upload_etag(&headers, &etag).map_err(|_| ())?;
        progress(binding, "ingest_intent", None, None, persist)?;
        let ingest = self
            .transition_import_request(
                binding,
                json!({"action":"ingest","etag":etag,"filename":init.filename}),
                credential,
            )
            .await?;
        if crate::d1_import::d1_import_action_provider_error(&ingest) {
            let bookmark = ingest
                .result
                .get("at_bookmark")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty());
            private_error::persist(binding, "ingest", &ingest, bookmark, persist)?;
            return Err(());
        }
        let bookmark = match classify_d1_import_ingest_response(&ingest)? {
            D1ImportIngestOutcome::Complete {
                at_bookmark,
                final_bookmark,
            } => return complete(binding, &at_bookmark, &final_bookmark, persist),
            D1ImportIngestOutcome::InProgress(bookmark) => bookmark,
        };
        // Resume identity must be durable before the first poll. No automatic re-ingest.
        progress(binding, "ingest_accepted", Some(&bookmark), None, persist)?;
        self.poll_transition(binding, &bookmark, credential, persist)
            .await
    }

    async fn poll_transition<S>(
        &self,
        binding: &ValidatedImport,
        bookmark: &str,
        credential: &AuthCredential,
        persist: &mut S,
    ) -> Result<Terminal, ()>
    where
        S: FnMut(&Progress) -> Result<String, ()>,
    {
        for _ in 0..60 {
            progress(binding, "poll_intent", Some(bookmark), None, persist)?;
            let response = self
                .transition_import_request(
                    binding,
                    json!({"action":"poll","at_bookmark":bookmark}),
                    credential,
                )
                .await?;
            if crate::d1_import::d1_import_action_provider_error(&response)
                && response.result.get("at_bookmark").and_then(Value::as_str) == Some(bookmark)
            {
                private_error::persist(binding, "poll", &response, Some(bookmark), persist)?;
                return Err(());
            }
            match classify_d1_import_poll_response(&response, bookmark)? {
                D1ImportPollOutcome::Complete(final_bookmark) => {
                    return complete(binding, bookmark, final_bookmark, persist);
                }
                D1ImportPollOutcome::InProgress => {
                    progress(binding, "poll_pending", Some(bookmark), None, persist)?;
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                }
                D1ImportPollOutcome::ProviderError => return Err(()),
            }
        }
        Err(())
    }
}

fn progress<S>(
    binding: &ValidatedImport,
    phase: &'static str,
    bookmark: Option<&str>,
    terminal: Option<TransportReceipt>,
    persist: &mut S,
) -> Result<String, ()>
where
    S: FnMut(&Progress) -> Result<String, ()>,
{
    let digest = persist(&Progress {
        operation_id: binding.checkpoint.operation_id.clone(),
        database_id: binding.database_id.clone(),
        phase,
        at_bookmark: bookmark.map(str::to_owned),
        terminal_bookmark: None,
        provider_error: None,
        terminal,
    })?;
    if !canonical_digest(&digest) {
        return Err(());
    }
    Ok(digest)
}

fn complete<S>(
    binding: &ValidatedImport,
    bookmark: &str,
    final_bookmark: &str,
    persist: &mut S,
) -> Result<Terminal, ()>
where
    S: FnMut(&Progress) -> Result<String, ()>,
{
    let bookmark_sha256 = format!(
        "sha256:{}",
        hex::encode(Sha256::digest(final_bookmark.as_bytes()))
    );
    let receipt = TransportReceipt {
        schema_version: 1,
        kind: TRANSPORT_RECEIPT_KIND.into(),
        operation_id: binding.checkpoint.operation_id.clone(),
        database_id: binding.database_id.clone(),
        transport: TRANSPORT.into(),
        execution_sha256: binding.checkpoint.identity.execution_sha256.clone(),
        stage: Stage::Committed,
        bookmark_sha256: bookmark_sha256.clone(),
        provider_error_evidence_hash: None,
        continuation: binding.continuation.clone(),
    };
    let receipt_sha256 = persist(&Progress {
        operation_id: binding.checkpoint.operation_id.clone(),
        database_id: binding.database_id.clone(),
        phase: "complete",
        at_bookmark: Some(bookmark.into()),
        terminal_bookmark: Some(final_bookmark.into()),
        terminal: Some(receipt),
        provider_error: None,
    })?;
    if !canonical_digest(&receipt_sha256) {
        return Err(());
    }
    Ok(Terminal::Committed {
        receipt_sha256,
        bookmark_sha256,
    })
}

#[cfg(test)]
mod tests;
