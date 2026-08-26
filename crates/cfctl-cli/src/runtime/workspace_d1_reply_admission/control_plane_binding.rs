use std::fs;

use super::super::{
    cli_io,
    prelude::{CliError, ProfileMetadata, Result},
};
use super::{Candidate, hex_sha};

pub(super) fn validate(
    candidate: &Candidate,
    authority: (&ProfileMetadata, &str, &str, &str),
) -> Result<()> {
    let (profile, account_id, generation, production_database_id) = authority;
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
            hex_sha(generation.as_bytes()),
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
    Ok(())
}
