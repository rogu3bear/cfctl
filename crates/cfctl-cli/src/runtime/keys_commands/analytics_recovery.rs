//! Unknown-identity bootstrap joins the existing analytics rotation owner.
//! A durable attempt blocks replay; it is never a token-revocation receipt.
use super::super::prelude::{
    CliError, KeyRenewAnalyticsProfileArgs, ProfileKind, ProfileMetadata, Result, ResultEnvelopeV2,
    StandingAuthorityV1, StateStore, Uuid, json,
};
use cfctl_core::hash_value;
use cfctl_storage::PrivateDirectory;
use serde::{Deserialize, Serialize};
use std::{fs, io::Read as _, path::Path};
mod rotation_attempt;
use rotation_attempt::RotationAttempt;

// Exact account/zone analytics read groups from the governed permission
// inventory. A changed group identity needs a reviewed contract update.
const READ_GROUPS: [&str; 2] = [
    "9c88f9c5bce24ce7af9a958ba9c504db",
    "b89a480218d04ceb98b4fe57ca29dc1f",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Request {
    pub schema_version: u8,
    pub profile: String,
    pub publisher_generation: String,
    pub minter_profile: String,
    pub minter_generation: String,
    pub account: String,
    pub zone: String,
    pub hostname: String,
    pub authority_id: String,
    pub authority_content_hash: String,
    pub permission_group_ids: Vec<String>,
    pub ttl_hours: u32,
    pub old_token_disposition: OldTokenDisposition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum OldTokenDisposition {
    UnknownNotRevoked,
}

fn rejected(message: &str) -> CliError {
    CliError::Input(format!("unmanaged analytics recovery: {message}"))
}

fn canonical_uuid(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|id| id.to_string() == value)
}

impl Request {
    pub(super) fn validate(
        &self,
        args: &KeyRenewAnalyticsProfileArgs,
        publisher: &ProfileMetadata,
        minter: &ProfileMetadata,
        authority: &StandingAuthorityV1,
    ) -> Result<()> {
        let mut groups = self.permission_group_ids.clone();
        groups.sort();
        let mut requested = args.permissions.clone();
        requested.sort();
        if self.schema_version != 1
            || self.profile.is_empty()
            || self.profile.len() > 128
            || self.minter_profile.is_empty()
            || self.minter_profile.len() > 128
            || self.hostname.is_empty()
            || self.hostname.len() > 253
            || !canonical_uuid(&self.publisher_generation)
            || !canonical_uuid(&self.minter_generation)
            || self.profile != args.profile
            || self.minter_profile != args.minter_profile
            || self.profile == self.minter_profile
            || self.account != args.account
            || self.zone != args.zone
            || self.hostname != args.hostname
            || self.authority_id != args.under_policy
            || self.authority_id != authority.authority_id
            || self.authority_content_hash != authority.content_hash
            || self.account != authority.account_id
            || authority.zone_id.as_deref() != Some(self.zone.as_str())
            || groups.len() != 2
            || groups.iter().any(|group| {
                group.len() != 32 || !group.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
            || groups[0] == groups[1]
            || groups.iter().map(String::as_str).ne(READ_GROUPS)
            || groups != requested
            || groups != authority.permission_group_ids
            || authority.capability_ids.len() != 2
            || !authority
                .capability_ids
                .iter()
                .any(|id| id == "account-api-tokens-create-token")
            || !authority
                .capability_ids
                .iter()
                .any(|id| id == "account-api-tokens-delete-token")
            || self.ttl_hours != args.ttl_hours
            || self.ttl_hours > authority.max_child_ttl_hours
            || args.current_token_id.is_some()
        {
            return Err(rejected(
                "request, target, groups or approved authority binding differs",
            ));
        }
        for (profile, id, generation) in [
            (publisher, &self.profile, &self.publisher_generation),
            (minter, &self.minter_profile, &self.minter_generation),
        ] {
            if profile.id != *id
                || profile.kind != ProfileKind::ApiToken
                || profile.emergency_only
                || profile.account_id.as_deref() != Some(self.account.as_str())
                || profile.credential_generation_id.as_deref() != Some(generation.as_str())
            {
                return Err(rejected("profile identity, account or generation drifted"));
            }
        }
        if publisher.managed_api_token.is_some() {
            return Err(rejected(
                "publisher is already managed; do not replay bootstrap",
            ));
        }
        Ok(())
    }
}

fn read_request(path: &Path) -> Result<Request> {
    if !fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_file()) {
        return Err(rejected(
            "request must be a bounded regular file without a symbolic link",
        ));
    }
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .map_err(|error| rejected(&format!("request is unreadable: {error}")))?;
    if !file.metadata().is_ok_and(|metadata| metadata.is_file()) {
        return Err(rejected("opened request is not a regular file"));
    }
    let mut bytes = Vec::new();
    file.take(65_537)
        .read_to_end(&mut bytes)
        .map_err(|error| rejected(&format!("request read failed: {error}")))?;
    if bytes.len() > 65_536 {
        return Err(rejected("request exceeds 64 KiB"));
    }
    Ok(serde_json::from_slice(&bytes)?)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Phase {
    AttemptPending,
    ActiveUnknownOld,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema_version: u8,
    request: Request,
    request_sha256: String,
    prior_profile: ProfileMetadata,
    mint_operation_id: String,
    phase: Phase,
    new_token_id: Option<String>,
    new_slot_id: Option<String>,
    active_profile: Option<ProfileMetadata>,
    verification_evidence: Vec<String>,
}

pub(super) struct Session {
    directory: PrivateDirectory,
    _lock: fs::File,
    request: Option<Request>,
    record: Option<Record>,
    ordinary: Option<RotationAttempt>,
}

impl Session {
    /// The per-profile guard also serializes ordinary hourly renewal. Existing
    /// incomplete bootstrap attempts stop before any network or new mint plan.
    pub(super) fn open(store: &StateStore, args: &KeyRenewAnalyticsProfileArgs) -> Result<Self> {
        let data = store.paths().data_dir.canonicalize().map_err(|error| {
            rejected(&format!(
                "runtime data directory cannot be resolved: {error}"
            ))
        })?;
        let root = PrivateDirectory::create(&data.join("analytics-profile-renewals"))?;
        let key = hash_value(&json!({"profile":args.profile}))?;
        let directory = PrivateDirectory::create(&root.location().join(key))?;
        let lock = directory.lock(true)?;
        let ordinary = RotationAttempt::load(&directory, store, args)?;
        let record: Option<Record> = directory
            .read("unmanaged-recovery.json", 65_536)?
            .map(|bytes| serde_json::from_slice(&bytes))
            .transpose()?;
        if let Some(record) = &record {
            if record.schema_version != 1
                || record.request.profile != args.profile
                || record.request_sha256 != hash_value(&serde_json::to_value(&record.request)?)?
                || !canonical_uuid(&record.mint_operation_id)
                || record.phase == Phase::AttemptPending
            {
                return Err(rejected(&format!(
                    "an existing attempt is incomplete or invalid; inspect its retained mint operation {} and profile readback; do not mint again",
                    record.mint_operation_id
                )));
            }
            if args.unmanaged_recovery.is_some() {
                return Err(rejected(
                    "bootstrap already consumed; use ordinary managed renewal",
                ));
            }
        }
        let request = args
            .unmanaged_recovery
            .as_deref()
            .map(read_request)
            .transpose()?;
        Ok(Self {
            directory,
            _lock: lock,
            request,
            record,
            ordinary,
        })
    }

    pub(super) fn authorize(
        &self,
        args: &KeyRenewAnalyticsProfileArgs,
        publisher: &ProfileMetadata,
        minter: &ProfileMetadata,
        authority: &StandingAuthorityV1,
    ) -> Result<()> {
        if let Some(request) = &self.request {
            request.validate(args, publisher, minter, authority)?;
        }
        Ok(())
    }

    pub(super) fn is_unmanaged_recovery(&self) -> bool {
        self.request.is_some()
    }

    pub(super) fn has_unknown_predecessor(&self) -> bool {
        self.record.is_some()
    }

    /// Persist before run: even a failed or uncertain execution cannot cause a
    /// scheduled invocation to mint a successor. The governed plan owns repair.
    pub(super) fn claim_mint(
        &mut self,
        store: &StateStore,
        args: &KeyRenewAnalyticsProfileArgs,
        publisher: &ProfileMetadata,
        plan: &ResultEnvelopeV2,
    ) -> Result<()> {
        if !plan.ok || plan.performed {
            return Err(rejected(
                "claim requires an unexecuted successful mint plan",
            ));
        }
        let operation = plan
            .operation_id
            .as_deref()
            .filter(|id| canonical_uuid(id))
            .ok_or_else(|| rejected("mint plan omitted a canonical operation ID"))?;
        let cfctl_storage::StoredPlanRecord::Current(pinned) =
            store.load_stored_plan_record(operation)?
        else {
            return Err(rejected("mint operation has no current pinned PlanV2"));
        };
        pinned.validate()?;
        let profiles = super::ProfilesConfig::load(store)?;
        require_unchanged(profiles.profiles.get(&args.profile), publisher)?;
        let minter = profiles
            .profiles
            .get(&args.minter_profile)
            .ok_or_else(|| rejected("minter disappeared before mint boundary"))?;
        let authority = store.load_authority(&args.under_policy)?;
        authority.ensure_operational()?;
        if pinned.plan.capability.id != "account-api-tokens-create-token"
            || pinned.plan.profile_id != args.minter_profile
            || pinned.plan.account_id != args.account
            || minter.credential_generation_id.as_deref()
                != Some(pinned.pins.credential_generation_id.as_str())
        {
            return Err(rejected("mint plan minter generation or account drifted"));
        }
        if let Some(request) = &self.request {
            request.validate(args, publisher, minter, &authority)?;
            self.persist_attempt(publisher, operation)
        } else {
            self.ordinary = Some(RotationAttempt::claim(
                &self.directory,
                self.ordinary.as_ref(),
                args,
                publisher,
                operation,
            )?);
            Ok(())
        }
    }

    fn persist_attempt(&mut self, publisher: &ProfileMetadata, operation: &str) -> Result<()> {
        let request = self
            .request
            .as_ref()
            .ok_or_else(|| rejected("bootstrap request is absent"))?;
        let record = Record {
            schema_version: 1,
            request: request.clone(),
            request_sha256: hash_value(&serde_json::to_value(request)?)?,
            prior_profile: publisher.clone(),
            mint_operation_id: operation.to_owned(),
            phase: Phase::AttemptPending,
            new_token_id: None,
            new_slot_id: None,
            active_profile: None,
            verification_evidence: Vec::new(),
        };
        self.directory.publish_new_file(
            "unmanaged-recovery.json", &serde_json::to_vec(&record)?,
            std::time::Instant::now() + std::time::Duration::from_secs(5),
        ).map_err(|error| rejected(&format!(
            "attempt publication failed (published={}); inspect retained state before retrying", error.published
        )))?;
        self.record = Some(record);
        Ok(())
    }

    pub(super) fn retain_child(&mut self, token_id: &str, slot_id: &str) -> Result<()> {
        if let Some(attempt) = &mut self.ordinary
            && self.request.is_none()
        {
            attempt.retain_child(&self.directory, token_id, slot_id)?;
        }
        if let Some(record) = &mut self.record
            && self.request.is_some()
        {
            record.new_token_id = Some(token_id.to_owned());
            record.new_slot_id = Some(slot_id.to_owned());
            self.directory
                .write("unmanaged-recovery.json", &serde_json::to_vec(record)?)?;
        }
        Ok(())
    }

    pub(super) fn retain_activation(&mut self, active: &ProfileMetadata) -> Result<()> {
        if let Some(attempt) = &mut self.ordinary
            && self.request.is_none()
        {
            attempt.retain_activation(&self.directory, active)?;
        }
        Ok(())
    }

    pub(super) fn close_ordinary(
        &mut self,
        store: &StateStore,
        operation: &str,
        profile: &ProfileMetadata,
        cleaned_child: bool,
    ) -> Result<()> {
        if let Some(attempt) = &mut self.ordinary
            && self.request.is_none()
        {
            attempt.close(&self.directory, store, operation, profile, cleaned_child)?;
        }
        Ok(())
    }

    pub(super) fn complete(
        &mut self,
        active: &ProfileMetadata,
        evidence: &[cfctl_core::EvidenceV1],
        staged_reads: &[ResultEnvelopeV2],
        active_reads: &[ResultEnvelopeV2],
    ) -> Result<()> {
        if !super::analytics_reads_passed(staged_reads)
            || !super::analytics_reads_passed(active_reads)
        {
            return Err(rejected(
                "three staged and three active native reads must all pass",
            ));
        }
        let record = self
            .record
            .as_mut()
            .ok_or_else(|| rejected("attempt record is absent"))?;
        let managed = active
            .managed_api_token
            .as_ref()
            .ok_or_else(|| rejected("active child is unmanaged"))?;
        if record.phase != Phase::AttemptPending
            || record.new_token_id.as_deref() != Some(managed.token_id.as_str())
            || record.new_slot_id != active.api_token_slot_id
            || active.credential_generation_id == record.prior_profile.credential_generation_id
            || active.account_id != record.prior_profile.account_id
            || active.id != record.prior_profile.id
            || active.kind != ProfileKind::ApiToken
            || active.emergency_only
        {
            return Err(rejected("completion differs from retained child or target"));
        }
        record.active_profile = Some(active.clone());
        record.verification_evidence = evidence
            .iter()
            .map(|entry| entry.content_hash.clone())
            .collect();
        record.phase = Phase::ActiveUnknownOld;
        self.directory
            .write("unmanaged-recovery.json", &serde_json::to_vec(record)?)?;
        Ok(())
    }

    pub(super) fn annotate(&self, envelope: &mut ResultEnvelopeV2) {
        if let Some(record) = &self.record
            && let Some(result) = envelope.result.as_object_mut()
        {
            result.insert(
                "unmanaged_predecessor".to_owned(),
                json!({
                    "old_credential_generation_id":record.request.publisher_generation,
                    "disposition":"unknown_not_revoked",
                    "cleanup_verified":false,
                    "bootstrap_mint_operation_id":record.mint_operation_id,
                    "record":self.directory.location().join("unmanaged-recovery.json"),
                    "automatic_revoke_permitted":false
                }),
            );
        }
    }
}

pub(super) fn require_unchanged(
    current: Option<&ProfileMetadata>,
    expected: &ProfileMetadata,
) -> Result<()> {
    if current != Some(expected) {
        return Err(rejected(
            "profile changed; activation or rollback refused without overwriting concurrent work",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
