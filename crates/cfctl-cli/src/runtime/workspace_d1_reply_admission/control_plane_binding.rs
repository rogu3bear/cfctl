use std::fs;

use chrono::Utc;

use super::super::{
    cli_io,
    prelude::{CliError, ProfileMetadata, Result},
};
use super::{Candidate, hex_sha, validate_candidate_bytes, validate_candidate_fresh};

pub(super) fn validate_candidate(
    bytes: &[u8],
    profile: &ProfileMetadata,
    account_id: &str,
    credential_generation: &str,
    production_database_id: &str,
) -> Result<Candidate> {
    let candidate = validate_candidate_bytes(bytes)?;
    validate_candidate_fresh(&candidate, Utc::now())?;
    let executable = std::env::current_exe().map_err(|error| {
        CliError::Input(format!("cfctl executable identity is unavailable: {error}"))
    })?;
    let executable_bytes = fs::read(&executable).map_err(|error| cli_io(&executable, error))?;
    for (label, actual, expected) in [
        (
            "cfctl build",
            hex_sha(&executable_bytes),
            candidate.cfctl_build_sha256.as_str(),
        ),
        (
            "profile",
            hex_sha(profile.id.as_bytes()),
            candidate.profile_sha256.as_str(),
        ),
        (
            "account",
            hex_sha(account_id.as_bytes()),
            candidate.account_sha256.as_str(),
        ),
        (
            "credential generation",
            hex_sha(credential_generation.as_bytes()),
            candidate.credential_generation_sha256.as_str(),
        ),
        (
            "production database",
            hex_sha(production_database_id.as_bytes()),
            candidate.production_database_sha256.as_str(),
        ),
    ] {
        if actual != expected {
            return Err(CliError::Input(format!(
                "reply-admission candidate {label} binding does not match the selected control plane"
            )));
        }
    }
    Ok(candidate)
}
