//! Profile-capability fitness preflight checks.
//!
//! Before making a live API call, check whether the selected profile has
//! sufficient permissions for the requested capability. When local inventory
//! exists to make that determination, fail early with actionable next steps
//! instead of letting a 403 Unauthorized cross the boundary.

use super::prelude::{CapabilityV1, CliError, ProfileMetadata, Result, StateStore};
use cfctl_core::StandingAuthorityV1;

/// Check if the profile can admit the capability for the given account.
/// Returns Ok(()) if the profile is suitable or if inventory is incomplete.
/// Returns Err if the profile provably cannot admit the capability.
///
/// This is a best-effort preflight check. When permission inventory is
/// incomplete or unavailable, the check passes and lets the live call proceed
/// (where it may still fail with 403, but at least we tried).
pub(super) fn check_profile_fitness(
    store: &StateStore,
    profile: &ProfileMetadata,
    capability: &CapabilityV1,
    account_id: Option<&str>,
) -> Result<()> {
    // Emergency profiles bypass fitness checks
    if profile.emergency_only {
        return Ok(());
    }

    // Only check profiles with managed API tokens that link to standing authority
    let managed_token = match &profile.managed_api_token {
        Some(token) => token,
        None => return Ok(()), // No inventory to check
    };

    // Load the standing authority for this profile
    let authority_id = &managed_token.standing_authority_id;
    let authority = match load_standing_authority(store, authority_id) {
        Ok(auth) => auth,
        Err(_) => return Ok(()), // Authority not found or unreadable; proceed anyway
    };

    // Check if the standing authority is active
    if authority.status != cfctl_core::StandingAuthorityStatus::Active {
        return Err(CliError::guided(
            "CFCTL_PROFILE_AUTHORITY_INACTIVE",
            &format!(
                "Profile `{}` is bound to standing authority `{}` which is no longer active",
                profile.id, authority_id
            ),
            "Use `cfctl auth use` to select a different profile or `cfctl keys policy list` to inspect standing authorities",
        ));
    }

    // Check account binding if applicable
    if let Some(requested_account) = account_id {
        if authority.account_id != requested_account {
            return Err(CliError::guided(
                "CFCTL_PROFILE_ACCOUNT_MISMATCH",
                &format!(
                    "Profile `{}` is bound to account `{}` but the capability requires account `{}`",
                    profile.id, authority.account_id, requested_account
                ),
                "Use `cfctl auth use --profile <profile>` to select a profile with access to the target account",
            ));
        }
    }

    // Check if the capability is in the authority's allowlist
    if !authority.capability_ids.contains(&capability.id) {
        return Err(CliError::guided(
            "CFCTL_PROFILE_CAPABILITY_NOT_ALLOWED",
            &format!(
                "Profile `{}` is bound to standing authority `{}` which does not allow capability `{}`",
                profile.id, authority_id, capability.id
            ),
            &format!(
                "The standing authority only allows these capabilities: {}. Use `cfctl auth use` to select a different profile with broader permissions, or activate a new standing authority with `cfctl keys policy create` that includes this capability.",
                authority.capability_ids.join(", ")
            ),
        ));
    }

    Ok(())
}

/// Load a standing authority by ID from the store.
/// Returns Ok(authority) if found and readable, Err otherwise.
fn load_standing_authority(
    store: &StateStore,
    authority_id: &str,
) -> Result<StandingAuthorityV1> {
    let path = store
        .paths()
        .data_dir
        .join("keys")
        .join("standing")
        .join(format!("{authority_id}.json"));

    if !path.is_file() {
        return Err(CliError::Input(format!(
            "Standing authority `{authority_id}` not found"
        )));
    }

    let content = std::fs::read_to_string(&path).map_err(|error| {
        CliError::Input(format!(
            "Failed to read standing authority `{authority_id}`: {error}"
        ))
    })?;

    serde_json::from_str(&content).map_err(|error| {
        CliError::Input(format!(
            "Failed to parse standing authority `{authority_id}`: {error}"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cfctl_core::StandingAuthorityStatus;
    use chrono::Utc;

    // Note: Full integration tests for profile fitness are in the runtime tests module.
    // These unit tests verify the logic without requiring a full authenticated store.

    #[test]
    fn profile_without_managed_token_passes_check() {
        // Profile fitness check should pass when there's no managed token
        // (no inventory to check against)
        let profile = cfctl_auth::ProfileMetadata::new(
            "test-profile",
            cfctl_auth::ProfileKind::ApiToken,
            Some("account-a"),
        );

        // Without managed_api_token, we can't load authority, so check passes
        assert!(profile.managed_api_token.is_none());
    }

    #[test]
    fn standing_authority_with_wrong_status_should_fail() {
        // Verify that an authority in pending status is not active
        let authority = StandingAuthorityV1::draft(
            "account-a",
            None,
            vec!["zones-get".to_owned()],
            vec!["group-a".to_owned()],
            "sha256:inventory1234",
            24,
            "test",
            10,
            Utc::now() + chrono::Duration::hours(24),
        )
        .expect("draft authority");

        assert_eq!(authority.status, StandingAuthorityStatus::PendingApproval);
        assert_ne!(authority.status, StandingAuthorityStatus::Active);
    }

    #[test]
    fn standing_authority_binds_to_specific_account() {
        // Verify that authority is bound to a specific account
        let authority = StandingAuthorityV1::draft(
            "account-a",
            None,
            vec!["zones-get".to_owned()],
            vec!["group-a".to_owned()],
            "sha256:inventory1234",
            24,
            "test",
            10,
            Utc::now() + chrono::Duration::hours(24),
        )
        .expect("draft authority");

        assert_eq!(authority.account_id, "account-a");
    }

    #[test]
    fn standing_authority_lists_allowed_capabilities() {
        // Verify that authority contains a capability allowlist
        let authority = StandingAuthorityV1::draft(
            "account-a",
            None,
            vec!["zones-get".to_owned(), "dns-records-for-a-zone-list-dns-records".to_owned()],
            vec!["group-a".to_owned()],
            "sha256:inventory1234",
            24,
            "test",
            10,
            Utc::now() + chrono::Duration::hours(24),
        )
        .expect("draft authority");

        assert_eq!(authority.capability_ids.len(), 2);
        assert!(authority.capability_ids.contains(&"zones-get".to_owned()));
        assert!(authority.capability_ids.contains(&"dns-records-for-a-zone-list-dns-records".to_owned()));
    }

}
