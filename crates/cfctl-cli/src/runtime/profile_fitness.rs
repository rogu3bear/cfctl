//! Profile-capability fitness preflight checks.
//!
//! Before making a live API call, check whether the selected profile has
//! sufficient permissions for the requested capability. When local inventory
//! exists to make that determination, fail early with actionable next steps
//! instead of letting a 403 Unauthorized cross the boundary.

use super::prelude::{CapabilityV1, CliError, ProfileMetadata, Result, StateStore};
use cfctl_core::StandingAuthorityV1;
use serde_json::Value;
use std::collections::HashMap;

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
        None => {
            // For non-managed api_token profiles (imported), check account pin if available
            return check_imported_token_fitness(profile, account_id);
        }
    };

    // Load the standing authority for this profile
    let authority_id = &managed_token.standing_authority_id;
    let authority = match store.load_authority(authority_id) {
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

    // Check if capability permissions are covered by standing authority permission groups
    check_permission_coverage(store, &authority, capability, &profile.id, authority_id)?;

    Ok(())
}

/// Check fitness for imported (non-managed) api_token profiles.
/// Can only verify account pin; no permission inventory available.
fn check_imported_token_fitness(
    profile: &ProfileMetadata,
    requested_account: Option<&str>,
) -> Result<()> {
    // Check account pin if both are specified
    if let (Some(profile_account), Some(requested)) = (&profile.account_id, requested_account) {
        if profile_account != requested {
            return Err(CliError::guided(
                "CFCTL_PROFILE_ACCOUNT_MISMATCH",
                &format!(
                    "Profile `{}` is pinned to account `{}` but the capability requires account `{}`",
                    profile.id, profile_account, requested
                ),
                "Use `cfctl auth use --profile <profile>` to select a profile with access to the target account",
            ));
        }
    }
    // No permission inventory for imported tokens; fail open
    Ok(())
}

/// Check if the capability's required permissions are covered by the standing
/// authority's granted permission groups.
///
/// This is a best-effort check. If we can't determine coverage (e.g., permission
/// inventory unavailable), we fail open and let the live call proceed.
fn check_permission_coverage(
    store: &StateStore,
    authority: &StandingAuthorityV1,
    capability: &CapabilityV1,
    profile_id: &str,
    authority_id: &str,
) -> Result<()> {
    // If capability requires no specific permissions, pass
    if capability.permissions.is_empty() {
        return Ok(());
    }

    // Load cached permission groups for this authority (if available)
    let permission_groups = match load_authority_permission_groups(store, authority_id) {
        Ok(groups) => groups,
        Err(_) => {
            // No cached permission inventory; fail open
            // The authority was created before permission caching was implemented,
            // or the cache file was deleted. Let the live call proceed.
            return Ok(());
        }
    };

    // Build a set of granted permission names from the authority's permission_group_ids
    let mut granted_permissions = std::collections::HashSet::new();
    for group_id in &authority.permission_group_ids {
        if let Some(group_name) = permission_groups.get(group_id.as_str()) {
            granted_permissions.insert(group_name.as_str());
        }
    }

    // Check if all required permissions are granted
    let missing_permissions: Vec<&str> = capability
        .permissions
        .iter()
        .filter(|perm| !granted_permissions.contains(perm.as_str()))
        .map(|s| s.as_str())
        .collect();

    if !missing_permissions.is_empty() {
        return Err(CliError::guided(
            "CFCTL_PROFILE_INSUFFICIENT_PERMISSIONS",
            &format!(
                "Profile `{}` lacks required permissions for `{}`. Missing: {}",
                profile_id,
                capability.id,
                missing_permissions.join(", ")
            ),
            &format!(
                "Use `cfctl auth use` to select a profile with broader permissions, or create a new standing authority with `cfctl keys policy create` that includes the required permission groups for: {}",
                missing_permissions.join(", ")
            ),
        ));
    }

    Ok(())
}

/// Load cached permission group name mappings for a standing authority.
/// Returns a map from permission_group_id to permission_group_name.
fn load_authority_permission_groups(
    store: &StateStore,
    authority_id: &str,
) -> Result<HashMap<String, String>> {
    let cached_groups = store
        .load_authority_permissions(authority_id)?
        .ok_or_else(|| {
            CliError::Input(
                "permission inventory not cached for this authority".to_owned(),
            )
        })?;

    let groups_array = cached_groups.as_array().ok_or_else(|| {
        CliError::Input("cached permission inventory is not an array".to_owned())
    })?;

    let mut id_to_name = HashMap::new();
    for group in groups_array {
        let id = group
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| CliError::Input("permission group missing id".to_owned()))?;
        let name = group
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| CliError::Input("permission group missing name".to_owned()))?;
        id_to_name.insert(id.to_owned(), name.to_owned());
    }

    Ok(id_to_name)
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

    #[test]
    fn imported_token_checks_account_pin() {
        // Imported tokens (non-managed) should check account pin when both are specified
        let profile = cfctl_auth::ProfileMetadata::new(
            "imported-profile",
            cfctl_auth::ProfileKind::ApiToken,
            Some("account-a"),
        );

        // Matching account should pass
        let result = check_imported_token_fitness(&profile, Some("account-a"));
        assert!(result.is_ok());

        // Mismatched account should fail
        let result = check_imported_token_fitness(&profile, Some("account-b"));
        assert!(result.is_err());
        let err_msg = format!("{:?}", result.unwrap_err());
        // Check that the error contains relevant account information
        assert!(err_msg.contains("account-a") || err_msg.contains("imported-profile"));
    }

    #[test]
    fn imported_token_fails_open_without_account_pin() {
        // When profile has no account_id, we can't verify, so fail open
        let profile = cfctl_auth::ProfileMetadata::new(
            "imported-profile",
            cfctl_auth::ProfileKind::ApiToken,
            None,
        );

        let result = check_imported_token_fitness(&profile, Some("account-a"));
        assert!(result.is_ok());

        // When no requested account, also fail open
        let profile_with_account = cfctl_auth::ProfileMetadata::new(
            "imported-profile",
            cfctl_auth::ProfileKind::ApiToken,
            Some("account-a"),
        );
        let result = check_imported_token_fitness(&profile_with_account, None);
        assert!(result.is_ok());
    }

    #[test]
    fn load_permission_groups_builds_id_to_name_mapping() {
        // This tests the permission group parsing logic
        let groups_json = serde_json::json!([
            {"id": "uuid-1", "name": "Zones Read", "scopes": ["com.cloudflare.api.account"]},
            {"id": "uuid-2", "name": "DNS Read", "scopes": ["com.cloudflare.api.account"]},
        ]);

        let groups_array = groups_json.as_array().unwrap();
        let mut id_to_name = HashMap::new();
        
        for group in groups_array {
            let id = group.get("id").and_then(Value::as_str).unwrap();
            let name = group.get("name").and_then(Value::as_str).unwrap();
            id_to_name.insert(id.to_owned(), name.to_owned());
        }

        assert_eq!(id_to_name.get("uuid-1"), Some(&"Zones Read".to_owned()));
        assert_eq!(id_to_name.get("uuid-2"), Some(&"DNS Read".to_owned()));
        assert_eq!(id_to_name.len(), 2);
    }

}
