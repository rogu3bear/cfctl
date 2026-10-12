//! Durable fence for ordinary rotations, including process death before cutover.
//! Native plans remain the authority and verification owner; this is no retry grant.
use super::{canonical_uuid, rejected, require_unchanged};
use crate::{KeyRenewAnalyticsProfileArgs, runtime::prelude::Result};
use cfctl_auth::{ProfileKind, ProfileMetadata};
use cfctl_core::PlanStatus;
use cfctl_storage::{PrivateDirectory, StateStore};
use serde::{Deserialize, Serialize};

const FILE: &str = "ordinary-attempt.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RotationAttempt {
    schema_version: u8,
    prior_profile: ProfileMetadata,
    mint_operation_id: String,
    minter_profile: String,
    authority_id: String,
    zone: String,
    hostname: String,
    old_token_id: String,
    new_token_id: Option<String>,
    new_slot_id: Option<String>,
    intended_active_profile: Option<ProfileMetadata>,
    closed_by_verified_revoke: Option<String>,
}

impl RotationAttempt {
    pub(super) fn load(
        directory: &PrivateDirectory,
        store: &StateStore,
        args: &KeyRenewAnalyticsProfileArgs,
    ) -> Result<Option<Self>> {
        let attempt: Option<Self> = directory
            .read(FILE, 65_536)?
            .map(|bytes| serde_json::from_slice(&bytes))
            .transpose()?;
        if let Some(attempt) = &attempt {
            if attempt.schema_version != 1
                || !canonical_uuid(&attempt.mint_operation_id)
                || attempt.prior_profile.id != args.profile
                || attempt.old_token_id.is_empty()
                || attempt
                    .closed_by_verified_revoke
                    .as_deref()
                    .is_some_and(|id| !canonical_uuid(id))
            {
                return Err(rejected(
                    "ordinary rotation record is invalid; preserve it for reconciliation",
                ));
            }
            if attempt.closed_by_verified_revoke.is_none() {
                let profiles = super::super::ProfilesConfig::load(store)?;
                let current = profiles.profiles.get(&args.profile);
                if args.unmanaged_recovery.is_some()
                    || args.minter_profile != attempt.minter_profile
                    || args.under_policy != attempt.authority_id
                    || args.zone != attempt.zone
                    || args.hostname != attempt.hostname
                    || attempt.prior_profile.account_id.as_deref() != Some(args.account.as_str())
                    || !current.is_some_and(|profile| attempt.matches_pending_revoke(profile))
                {
                    return Err(rejected(&format!(
                        "ordinary mint attempt {} is unresolved; inspect its original plan and profile readback; no new mint or journal deletion is permitted",
                        attempt.mint_operation_id
                    )));
                }
                // Only the existing exact old-child revoke reconciliation can run.
                // claim() below independently refuses another mint while pending.
            }
        }
        Ok(attempt)
    }

    pub(super) fn claim(
        directory: &PrivateDirectory,
        previous: Option<&Self>,
        args: &KeyRenewAnalyticsProfileArgs,
        publisher: &ProfileMetadata,
        operation: &str,
    ) -> Result<Self> {
        if previous.is_some_and(|attempt| attempt.closed_by_verified_revoke.is_none()) {
            return Err(rejected(
                "ordinary rotation is still pending; another mint is forbidden",
            ));
        }
        let old_token_id = publisher
            .managed_api_token
            .as_ref()
            .map(|managed| managed.token_id.clone())
            .or_else(|| args.current_token_id.clone())
            .filter(|id| !id.trim().is_empty())
            .ok_or_else(|| rejected("ordinary rotation requires the known prior token identity"))?;
        if !canonical_uuid(operation) {
            return Err(rejected("ordinary mint operation identity is invalid"));
        }
        let attempt = Self {
            schema_version: 1,
            prior_profile: publisher.clone(),
            mint_operation_id: operation.to_owned(),
            minter_profile: args.minter_profile.clone(),
            authority_id: args.under_policy.clone(),
            zone: args.zone.clone(),
            hostname: args.hostname.clone(),
            old_token_id,
            new_token_id: None,
            new_slot_id: None,
            intended_active_profile: None,
            closed_by_verified_revoke: None,
        };
        // The per-profile lock owns this single pointer. Atomic replacement is
        // durable before run; prior native mint/revoke plans retain their history.
        attempt.persist(directory)?;
        Ok(attempt)
    }

    fn persist(&self, directory: &PrivateDirectory) -> Result<()> {
        directory.write(FILE, &serde_json::to_vec(self)?)?;
        Ok(())
    }

    pub(super) fn retain_child(
        &mut self,
        directory: &PrivateDirectory,
        token: &str,
        slot: &str,
    ) -> Result<()> {
        if self.closed_by_verified_revoke.is_some()
            || token.is_empty()
            || token == self.old_token_id
            || !canonical_uuid(slot)
        {
            return Err(rejected("ordinary child differs from pending attempt"));
        }
        self.new_token_id = Some(token.to_owned());
        self.new_slot_id = Some(slot.to_owned());
        self.persist(directory)
    }

    pub(super) fn retain_activation(
        &mut self,
        directory: &PrivateDirectory,
        active: &ProfileMetadata,
    ) -> Result<()> {
        if !self.matches_child(active) || self.closed_by_verified_revoke.is_some() {
            return Err(rejected("ordinary activation differs from retained child"));
        }
        self.intended_active_profile = Some(active.clone());
        self.persist(directory)
    }

    fn matches_child(&self, profile: &ProfileMetadata) -> bool {
        profile.id == self.prior_profile.id
            && profile.account_id == self.prior_profile.account_id
            && profile.kind == ProfileKind::ApiToken
            && !profile.emergency_only
            && profile.credential_generation_id != self.prior_profile.credential_generation_id
            && profile.api_token_slot_id.is_some()
            && profile.api_token_slot_id == self.new_slot_id
            && profile.managed_api_token.as_ref().is_some_and(|managed| {
                Some(managed.token_id.as_str()) == self.new_token_id.as_deref()
                    && managed.standing_authority_id == self.authority_id
            })
    }

    fn matches_pending_revoke(&self, profile: &ProfileMetadata) -> bool {
        let Some(managed) = &profile.managed_api_token else {
            return false;
        };
        if managed.pending_revoke_token_id.as_deref() != Some(self.old_token_id.as_str())
            || managed.pending_revoke_slot_id != self.prior_profile.api_token_slot_id
        {
            return false;
        }
        let mut normalized = profile.clone();
        if let Some(managed) = &mut normalized.managed_api_token {
            managed.pending_revoke_token_id = None;
            managed.pending_revoke_operation_id = None;
            managed.pending_revoke_slot_id = None;
        }
        self.matches_child(profile) && self.intended_active_profile.as_ref() == Some(&normalized)
    }

    pub(super) fn close(
        &mut self,
        directory: &PrivateDirectory,
        store: &StateStore,
        operation: &str,
        profile: &ProfileMetadata,
        cleaned_child: bool,
    ) -> Result<()> {
        let token = if cleaned_child {
            require_unchanged(Some(profile), &self.prior_profile)?;
            self.new_token_id.as_deref()
        } else {
            if self.intended_active_profile.as_ref() != Some(profile)
                || !self.matches_child(profile)
            {
                return Err(rejected(
                    "ordinary terminal profile differs from intended cutover",
                ));
            }
            Some(self.old_token_id.as_str())
        }
        .ok_or_else(|| rejected("ordinary close has no exact token identity"))?;
        // A current validated PlanV2 is required; an exit code, legacy projection
        // or caller boolean is insufficient to clear a possible provider effect.
        let cfctl_storage::StoredPlanRecord::Current(pinned) =
            store.load_stored_plan_record(operation)?
        else {
            return Err(rejected("ordinary close requires a current pinned PlanV2"));
        };
        pinned.validate()?;
        let plan = pinned.plan;
        if self.closed_by_verified_revoke.is_some()
            || plan.status != PlanStatus::Verified
            || plan.capability.id != "account-api-tokens-delete-token"
            || plan.profile_id != self.minter_profile
            || Some(plan.account_id.as_str()) != self.prior_profile.account_id.as_deref()
            || plan
                .input
                .pointer("/selectors/token_id")
                .and_then(serde_json::Value::as_str)
                != Some(token)
        {
            return Err(rejected(
                "ordinary close requires exact native Verified token revocation",
            ));
        }
        let profiles = super::super::ProfilesConfig::load(store)?;
        require_unchanged(profiles.profiles.get(&profile.id), profile)?;
        self.closed_by_verified_revoke = Some(operation.to_owned());
        self.persist(directory)
    }
}

#[cfg(test)]
mod tests;
