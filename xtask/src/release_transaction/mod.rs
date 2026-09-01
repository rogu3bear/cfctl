mod command;
mod staging;

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests;

use std::{collections::BTreeSet, fs, path::Path};

use command::{SystemCommandRunner, checked_output};
use staging::ReleaseStaging;

use crate::{MACOS_RELEASE_TARGETS, TaskError};

pub(super) fn release(
    certificate_identity: &str,
    certificate_oidc_issuer: &str,
    macos_signing_identity: &str,
    apple_notary_profile: &str,
) -> Result<(), TaskError> {
    let trust_roots = super::release_trust_roots()?;
    super::validate_release_identity_inputs(
        &trust_roots,
        certificate_identity,
        certificate_oidc_issuer,
        macos_signing_identity,
    )?;
    super::ensure_clean_source_tree()?;
    super::run("cosign", &["version"])?;
    super::run("xcrun", &["notarytool", "--version"])?;

    let commit = super::output("git", &["--no-replace-objects", "rev-parse", "HEAD"])?;
    let staging = ReleaseStaging::create(Path::new("target/release-proof/transactions"), &commit)?;
    super::assemble_into(&[], staging.dist(), staging.proof())?;

    let mut steps = SystemReleaseSteps {
        certificate_identity,
        certificate_oidc_issuer,
        macos_signing_identity,
        apple_notary_profile,
        trust_roots: &trust_roots,
        command_runner: SystemCommandRunner,
    };
    execute_transaction(&staging, Path::new("dist"), &mut steps)
}

trait ReleaseSteps {
    fn sign_macos(&mut self, dist: &Path, proof: &Path) -> Result<String, TaskError>;
    fn refresh_post_signing_derivatives(
        &mut self,
        dist: &Path,
        team_identifier: &str,
    ) -> Result<(), TaskError>;
    fn notarize(&mut self, dist: &Path, proof: &Path) -> Result<(), TaskError>;
    fn finalize_metadata(&mut self, dist: &Path) -> Result<(), TaskError>;
    fn sign_sigstore(&mut self, dist: &Path) -> Result<(), TaskError>;
    fn verify_exact(&mut self, dist: &Path, proof: &Path) -> Result<(), TaskError>;
}

fn execute_transaction(
    staging: &ReleaseStaging,
    final_dist: &Path,
    steps: &mut impl ReleaseSteps,
) -> Result<(), TaskError> {
    let team_identifier = steps.sign_macos(staging.dist(), staging.proof())?;
    steps.refresh_post_signing_derivatives(staging.dist(), &team_identifier)?;
    steps.notarize(staging.dist(), staging.proof())?;
    steps.finalize_metadata(staging.dist())?;
    steps.sign_sigstore(staging.dist())?;
    steps.verify_exact(staging.dist(), staging.proof())?;
    staging.promote(final_dist)
}

struct SystemReleaseSteps<'a> {
    certificate_identity: &'a str,
    certificate_oidc_issuer: &'a str,
    macos_signing_identity: &'a str,
    apple_notary_profile: &'a str,
    trust_roots: &'a super::ReleaseTrustRoots,
    command_runner: SystemCommandRunner,
}

impl ReleaseSteps for SystemReleaseSteps<'_> {
    fn sign_macos(&mut self, dist: &Path, proof: &Path) -> Result<String, TaskError> {
        if !self
            .macos_signing_identity
            .starts_with("Developer ID Application: ")
        {
            return Err(TaskError::InvalidMacosSignature(
                "the selected identity must be a Developer ID Application certificate".to_owned(),
            ));
        }
        if self.apple_notary_profile.trim().is_empty() {
            return Err(TaskError::InvalidNotarizationReceipt(
                "the Keychain notary profile name must not be empty".to_owned(),
            ));
        }

        let mut team_identifiers = BTreeSet::new();
        for target in MACOS_RELEASE_TARGETS {
            let artifact = dist.join(format!("cfctl-{target}"));
            let artifact_text = super::path_text(&artifact)?;
            super::run(
                "codesign",
                &[
                    "--force",
                    "--sign",
                    &self.trust_roots.macos_certificate_sha1,
                    "--options",
                    "runtime",
                    "--timestamp",
                    artifact_text,
                ],
            )?;
            let verification = super::output_combined(
                "codesign",
                &["--verify", "--strict", "--verbose=4", artifact_text],
            )?;
            super::reject_codesign_timestamp_mismatch(&verification)?;
            let details = super::output_combined("codesign", &["-dvvv", artifact_text])?;
            team_identifiers.insert(super::validate_codesign_details(
                &details,
                self.macos_signing_identity,
            )?);
            super::verify_macos_signing_certificate_at(
                &artifact,
                target,
                &self.trust_roots.macos_certificate_sha1,
                &self.trust_roots.macos_certificate_sha256,
                &proof.join("signature"),
            )?;
        }
        if team_identifiers.len() != 1 {
            return Err(TaskError::InvalidMacosSignature(
                "the two macOS binaries were not signed by the same team".to_owned(),
            ));
        }
        team_identifiers
            .into_iter()
            .next()
            .ok_or_else(|| TaskError::InvalidMacosSignature("missing TeamIdentifier".to_owned()))
    }

    fn refresh_post_signing_derivatives(
        &mut self,
        dist: &Path,
        team_identifier: &str,
    ) -> Result<(), TaskError> {
        for target in MACOS_RELEASE_TARGETS {
            let artifact = dist.join(format!("cfctl-{target}"));
            super::run(
                "syft",
                &[
                    &format!("file:{}", artifact.display()),
                    "-o",
                    &format!("spdx-json={}.spdx.json", artifact.display()),
                ],
            )?;
        }
        let _formula = super::render_homebrew_formula(dist)?;
        let _installer = super::render_linux_installer(
            dist,
            Some((self.certificate_identity, self.certificate_oidc_issuer)),
        )?;
        let provenance_path = dist.join("provenance.json");
        let mut provenance: serde_json::Value = serde_json::from_slice(
            &fs::read(&provenance_path)
                .map_err(|source| super::io_error(&provenance_path, source))?,
        )
        .map_err(|error| TaskError::InvalidProvenance(error.to_string()))?;
        provenance["artifacts"] = serde_json::json!(
            super::expected_unsigned_release_file_names()
                .into_iter()
                .filter(|name| name != "provenance.json")
                .collect::<Vec<_>>()
        );
        provenance["macos_distribution"] = serde_json::json!({
            "signing_identity": self.macos_signing_identity,
            "team_identifier": team_identifier,
            "certificate_sha1": self.trust_roots.macos_certificate_sha1,
            "certificate_sha256": self.trust_roots.macos_certificate_sha256,
            "hardened_runtime": true,
            "secure_timestamp": true,
            "notarization_receipts": MACOS_RELEASE_TARGETS
                .iter()
                .map(|target| format!("notary-{target}.json"))
                .collect::<Vec<_>>(),
        });
        fs::write(
            &provenance_path,
            serde_json::to_vec_pretty(&provenance)
                .map_err(|error| TaskError::InvalidProvenance(error.to_string()))?,
        )
        .map_err(|source| super::io_error(&provenance_path, source))?;
        super::remove_file_if_present(&dist.join("SHA256SUMS"))
    }

    fn notarize(&mut self, dist: &Path, proof: &Path) -> Result<(), TaskError> {
        for target in MACOS_RELEASE_TARGETS {
            notarize_macos_artifact(
                target,
                &dist.join(format!("cfctl-{target}")),
                self.apple_notary_profile,
                dist,
                &proof.join("notary").join(target),
                &mut self.command_runner,
            )?;
        }
        Ok(())
    }

    fn finalize_metadata(&mut self, dist: &Path) -> Result<(), TaskError> {
        super::write_checksums(
            &dist.join("SHA256SUMS"),
            &super::unsigned_release_artifact_paths_at(dist),
        )
    }

    fn sign_sigstore(&mut self, dist: &Path) -> Result<(), TaskError> {
        let sums = dist.join("SHA256SUMS");
        let sums_bundle = dist.join("SHA256SUMS.sigstore.json");
        super::run(
            "cosign",
            &[
                "sign-blob",
                "--yes",
                "--bundle",
                super::path_text(&sums_bundle)?,
                super::path_text(&sums)?,
            ],
        )?;
        let provenance = dist.join("provenance.json");
        let provenance_bundle = dist.join("provenance.sigstore.json");
        super::run(
            "cosign",
            &[
                "sign-blob",
                "--yes",
                "--bundle",
                super::path_text(&provenance_bundle)?,
                super::path_text(&provenance)?,
            ],
        )
    }

    fn verify_exact(&mut self, dist: &Path, proof: &Path) -> Result<(), TaskError> {
        super::verify_signed_release_at(
            dist,
            proof,
            self.certificate_identity,
            self.certificate_oidc_issuer,
            self.macos_signing_identity,
            self.trust_roots,
        )?;
        Ok(())
    }
}

fn notarize_macos_artifact(
    target: &str,
    artifact: &Path,
    notary_profile: &str,
    dist: &Path,
    work: &Path,
    runner: &mut SystemCommandRunner,
) -> Result<(), TaskError> {
    fs::create_dir_all(work).map_err(|source| super::io_error(work, source))?;
    let archive = work.join(format!("cfctl-{target}.zip"));
    super::remove_file_if_present(&archive)?;
    super::run(
        "ditto",
        &[
            "-c",
            "-k",
            "--keepParent",
            super::path_text(artifact)?,
            super::path_text(&archive)?,
        ],
    )?;

    let submission_text = checked_output(
        runner,
        "xcrun",
        &[
            "notarytool",
            "submit",
            super::path_text(&archive)?,
            "--keychain-profile",
            notary_profile,
            "--no-progress",
            "--output-format",
            "json",
        ],
        &format!("notarytool submit for {target}"),
    )?;
    let submission: serde_json::Value =
        serde_json::from_str(&submission_text).map_err(|error| {
            TaskError::InvalidNotarizationReceipt(format!(
                "notarytool returned invalid JSON for {target}: {error}"
            ))
        })?;
    let submission_id = submission
        .get("id")
        .and_then(serde_json::Value::as_str)
        .filter(|id| !id.trim().is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            TaskError::InvalidNotarizationReceipt(format!(
                "notarytool submit omitted the submission id for {target}"
            ))
        })?;
    let artifact_hash = super::sha256_file(artifact)?;
    let pending =
        super::notary_receipt_document(target, &artifact_hash, &submission_id, submission);
    write_notary_receipt(target, dist, work, &pending)?;

    let completed_text = checked_output(
        runner,
        "xcrun",
        &[
            "notarytool",
            "wait",
            &submission_id,
            "--keychain-profile",
            notary_profile,
            "--timeout",
            "1h",
            "--no-progress",
            "--output-format",
            "json",
        ],
        &format!("notarytool wait for {target}"),
    )?;
    let completed: serde_json::Value = serde_json::from_str(&completed_text).map_err(|error| {
        TaskError::InvalidNotarizationReceipt(format!(
            "notarytool wait returned invalid JSON for {target}: {error}"
        ))
    })?;
    let receipt = super::notary_receipt_document(target, &artifact_hash, &submission_id, completed);
    write_notary_receipt(target, dist, work, &receipt)?;
    super::validate_notary_receipt_value(&receipt, target, &artifact_hash)
}

fn write_notary_receipt(
    target: &str,
    dist: &Path,
    work: &Path,
    receipt: &serde_json::Value,
) -> Result<(), TaskError> {
    let bytes = serde_json::to_vec_pretty(receipt).map_err(|error| {
        TaskError::InvalidNotarizationReceipt(format!("serialize receipt for {target}: {error}"))
    })?;
    let receipt_path = dist.join(format!("notary-{target}.json"));
    fs::write(&receipt_path, &bytes).map_err(|source| super::io_error(&receipt_path, source))?;
    let durable_path = work.join("receipt.json");
    fs::write(&durable_path, bytes).map_err(|source| super::io_error(&durable_path, source))
}
