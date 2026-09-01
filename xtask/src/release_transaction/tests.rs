use std::{
    collections::BTreeSet,
    fs, io,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use super::{
    ReleaseSteps,
    command::{CommandOutput, CommandRunner, checked_output},
    execute_transaction,
    staging::{PromotionFilesystem, ReleaseStaging},
};
use crate::{
    TaskError, expected_signed_release_file_names, sha256_file, validate_codesign_details,
};

#[derive(Default)]
struct FakeSteps {
    events: Vec<&'static str>,
    fail_at: Option<&'static str>,
    signed_hash_seen_by_notary: Option<String>,
}

struct FakeCommandRunner(Option<CommandOutput>);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PromotionCall {
    Inspect,
    Publish,
    Exchange,
    Retire,
}

struct FakePromotionFilesystem {
    calls: Vec<PromotionCall>,
    final_generation: Option<&'static str>,
    staged_generation: Option<&'static str>,
    exchange_error: Option<io::Error>,
    retirement_error: Option<io::Error>,
    public_absence_observed: bool,
}

impl FakePromotionFilesystem {
    fn first_publication() -> Self {
        Self {
            calls: Vec::new(),
            final_generation: None,
            staged_generation: Some("new"),
            exchange_error: None,
            retirement_error: None,
            public_absence_observed: false,
        }
    }

    fn replacement() -> Self {
        Self {
            final_generation: Some("accepted"),
            ..Self::first_publication()
        }
    }

    fn observe_public_path(&mut self) {
        self.public_absence_observed |= self.final_generation.is_none();
    }
}

impl PromotionFilesystem for FakePromotionFilesystem {
    fn path_exists(&mut self, _path: &Path) -> io::Result<bool> {
        self.calls.push(PromotionCall::Inspect);
        Ok(self.final_generation.is_some())
    }

    fn publish_if_absent(&mut self, _staged: &Path, _final_dist: &Path) -> io::Result<()> {
        self.calls.push(PromotionCall::Publish);
        if self.final_generation.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "final distribution appeared",
            ));
        }
        self.final_generation = self.staged_generation.take();
        self.observe_public_path();
        Ok(())
    }

    fn exchange(&mut self, _staged: &Path, _final_dist: &Path) -> io::Result<()> {
        self.calls.push(PromotionCall::Exchange);
        if let Some(error) = self.exchange_error.take() {
            self.observe_public_path();
            return Err(error);
        }
        std::mem::swap(&mut self.staged_generation, &mut self.final_generation);
        self.observe_public_path();
        Ok(())
    }

    fn retire(&mut self, _retired: &Path) -> io::Result<()> {
        self.calls.push(PromotionCall::Retire);
        if let Some(error) = self.retirement_error.take() {
            self.observe_public_path();
            return Err(error);
        }
        self.staged_generation = None;
        self.observe_public_path();
        Ok(())
    }
}

impl CommandRunner for FakeCommandRunner {
    fn output(&mut self, _program: &str, _arguments: &[&str]) -> Result<CommandOutput, TaskError> {
        self.0
            .take()
            .ok_or_else(|| TaskError::Command("fake command was called twice".to_owned()))
    }
}

impl FakeSteps {
    fn fail(&self, step: &'static str) -> Result<(), TaskError> {
        if self.fail_at == Some(step) {
            Err(TaskError::Command(format!("injected {step} failure")))
        } else {
            Ok(())
        }
    }
}

impl ReleaseSteps for FakeSteps {
    fn sign_macos(&mut self, dist: &Path, _proof: &Path) -> Result<String, TaskError> {
        self.events.push("sign");
        self.fail("sign")?;
        let artifact = dist.join("cfctl-aarch64-apple-darwin");
        fs::write(&artifact, b"signed macOS bytes")
            .map_err(|source| crate::io_error(&artifact, source))?;
        Ok("TEAM123456".to_owned())
    }

    fn refresh_post_signing_derivatives(
        &mut self,
        dist: &Path,
        _team_identifier: &str,
    ) -> Result<(), TaskError> {
        self.events.push("refresh");
        self.fail("refresh")?;
        let digest = sha256_file(&dist.join("cfctl-aarch64-apple-darwin"))?;
        let formula = dist.join("cfctl.rb");
        fs::write(&formula, format!("sha256 {digest}\n"))
            .map_err(|source| crate::io_error(&formula, source))
    }

    fn notarize(&mut self, dist: &Path, _proof: &Path) -> Result<(), TaskError> {
        self.events.push("notarize");
        let signed_hash = sha256_file(&dist.join("cfctl-aarch64-apple-darwin"))?;
        let formula = fs::read_to_string(dist.join("cfctl.rb"))
            .map_err(|source| crate::io_error(&dist.join("cfctl.rb"), source))?;
        assert!(formula.contains(&signed_hash));
        self.signed_hash_seen_by_notary = Some(signed_hash);
        self.fail("notarize")
    }

    fn finalize_metadata(&mut self, dist: &Path) -> Result<(), TaskError> {
        self.events.push("finalize");
        self.fail("finalize")?;
        for name in expected_signed_release_file_names() {
            let path = dist.join(name);
            if !path.exists() {
                fs::write(&path, b"fixture").map_err(|source| crate::io_error(&path, source))?;
            }
        }
        Ok(())
    }

    fn sign_sigstore(&mut self, _dist: &Path) -> Result<(), TaskError> {
        self.events.push("sigstore");
        self.fail("sigstore")
    }

    fn verify_exact(&mut self, dist: &Path, _proof: &Path) -> Result<(), TaskError> {
        self.events.push("verify");
        self.fail("verify")?;
        let actual = fs::read_dir(dist)
            .map_err(|source| crate::io_error(dist, source))?
            .map(|entry| {
                entry
                    .map_err(|source| crate::io_error(dist, source))?
                    .file_name()
                    .into_string()
                    .map_err(|_| TaskError::Command("fixture name is not UTF-8".to_owned()))
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        assert_eq!(actual, expected_signed_release_file_names());
        Ok(())
    }
}

#[test]
fn failed_transaction_leaves_existing_distribution_untouched() {
    let root = temporary_root("failure-isolation");
    let final_dist = root.join("dist");
    fs::create_dir_all(&final_dist).expect("create final dist");
    fs::write(final_dist.join("accepted.txt"), b"previous release").expect("write prior release");
    let staging = staged_fixture(&root);
    let mut steps = FakeSteps {
        fail_at: Some("notarize"),
        ..FakeSteps::default()
    };

    assert!(execute_transaction(&staging, &final_dist, &mut steps).is_err());
    assert_eq!(
        fs::read(final_dist.join("accepted.txt")).expect("read prior release"),
        b"previous release"
    );
    assert!(
        staging.dist().exists(),
        "failed transaction evidence remains staged"
    );
    cleanup(&root);
}

#[test]
fn signed_derivatives_are_refreshed_before_notary_submission() {
    let root = temporary_root("post-signing-order");
    let final_dist = root.join("dist");
    let staging = staged_fixture(&root);
    let mut steps = FakeSteps::default();

    execute_transaction(&staging, &final_dist, &mut steps).expect("complete transaction");
    assert_eq!(
        steps.events,
        [
            "sign", "refresh", "notarize", "finalize", "sigstore", "verify"
        ]
    );
    assert!(steps.signed_hash_seen_by_notary.is_some());
    cleanup(&root);
}

#[test]
fn notary_diagnostics_are_bounded_and_redacted_without_losing_safe_context() {
    let output = CommandOutput {
        code: Some(69),
        stdout: b"submission rejected: developer account requires attention\n".to_vec(),
        stderr: format!("authorization: Bearer top-secret\n{}", "x".repeat(20_000)).into_bytes(),
    };

    let error = checked_output(
        &mut FakeCommandRunner(Some(output)),
        "xcrun",
        &[
            "notarytool",
            "submit",
            "--keychain-profile",
            "private-profile",
        ],
        "notarytool submit for aarch64-apple-darwin",
    )
    .expect_err("exit 69 must fail");
    let diagnostics = error.to_string();
    assert!(diagnostics.contains("submission rejected"));
    assert!(diagnostics.contains("[REDACTED]"));
    assert!(!diagnostics.contains("top-secret"));
    assert!(!diagnostics.contains("private-profile"));
    assert!(diagnostics.len() <= 4_192);
}

#[test]
fn codesign_timestamp_mismatch_is_rejected_even_when_a_timestamp_is_present() {
    let identity = "Developer ID Application: Example Corp (TEAM123456)";
    let details = concat!(
        "CodeDirectory v=20500 flags=0x10000(runtime)\n",
        "Authority=Developer ID Application: Example Corp (TEAM123456)\n",
        "Timestamp=Jul 14, 2026 at 10:30:00 PM\n",
        "TeamIdentifier=TEAM123456\n",
        "warning: timestamp mismatch of 2255 seconds\n",
    );

    assert!(validate_codesign_details(details, identity).is_err());
}

#[test]
fn only_the_exact_verified_staging_set_is_promoted() {
    let root = temporary_root("verified-promotion");
    let final_dist = root.join("dist");
    let staging = staged_fixture(&root);
    let mut steps = FakeSteps::default();

    execute_transaction(&staging, &final_dist, &mut steps).expect("complete transaction");
    let names = fs::read_dir(&final_dist)
        .expect("read promoted dist")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .into_string()
                .expect("UTF-8")
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(names, expected_signed_release_file_names());
    assert!(!staging.dist().exists());
    cleanup(&root);
}

#[test]
fn first_publication_atomically_renames_into_an_absent_final_path() {
    let root = temporary_root("first-publication");
    let staging = staged_fixture(&root);
    let mut filesystem = FakePromotionFilesystem::first_publication();

    staging
        .promote_with(&root.join("dist"), &mut filesystem)
        .expect("first publication");

    assert_eq!(filesystem.final_generation, Some("new"));
    assert_eq!(filesystem.staged_generation, None);
    assert_eq!(
        filesystem.calls,
        [PromotionCall::Inspect, PromotionCall::Publish]
    );
    cleanup(&root);
}

#[test]
fn replacement_uses_one_atomic_exchange_without_a_public_absence() {
    let root = temporary_root("atomic-replacement");
    let staging = staged_fixture(&root);
    let mut filesystem = FakePromotionFilesystem::replacement();

    staging
        .promote_with(&root.join("dist"), &mut filesystem)
        .expect("atomic replacement");

    assert_eq!(filesystem.final_generation, Some("new"));
    assert_eq!(filesystem.staged_generation, None);
    assert!(!filesystem.public_absence_observed);
    assert_eq!(
        filesystem.calls,
        [
            PromotionCall::Inspect,
            PromotionCall::Exchange,
            PromotionCall::Retire,
        ]
    );
    cleanup(&root);
}

#[test]
fn unsupported_exchange_leaves_the_accepted_final_untouched() {
    let root = temporary_root("unsupported-exchange");
    let staging = staged_fixture(&root);
    let mut filesystem = FakePromotionFilesystem::replacement();
    filesystem.exchange_error = Some(io::Error::new(
        io::ErrorKind::Unsupported,
        "atomic exchange unavailable",
    ));

    let error = staging
        .promote_with(&root.join("dist"), &mut filesystem)
        .expect_err("unsupported exchange must fail closed");

    assert_eq!(filesystem.final_generation, Some("accepted"));
    assert_eq!(filesystem.staged_generation, Some("new"));
    assert!(!filesystem.public_absence_observed);
    assert!(error.to_string().contains("atomic exchange unavailable"));
    assert_eq!(
        filesystem.calls,
        [PromotionCall::Inspect, PromotionCall::Exchange]
    );
    cleanup(&root);
}

#[test]
fn exchange_failure_preserves_both_generations_and_reports_the_cause() {
    let root = temporary_root("failed-exchange");
    let staging = staged_fixture(&root);
    let mut filesystem = FakePromotionFilesystem::replacement();
    filesystem.exchange_error = Some(io::Error::other("injected exchange failure"));

    let error = staging
        .promote_with(&root.join("dist"), &mut filesystem)
        .expect_err("failed exchange");

    assert_eq!(filesystem.final_generation, Some("accepted"));
    assert_eq!(filesystem.staged_generation, Some("new"));
    assert!(!filesystem.public_absence_observed);
    assert!(error.to_string().contains("injected exchange failure"));
    cleanup(&root);
}

#[test]
fn retirement_failure_reports_error_but_keeps_the_new_final_published() {
    let root = temporary_root("failed-retirement");
    let staging = staged_fixture(&root);
    let mut filesystem = FakePromotionFilesystem::replacement();
    filesystem.retirement_error = Some(io::Error::other("injected retirement failure"));

    let error = staging
        .promote_with(&root.join("dist"), &mut filesystem)
        .expect_err("failed retirement");

    assert_eq!(filesystem.final_generation, Some("new"));
    assert_eq!(filesystem.staged_generation, Some("accepted"));
    assert!(!filesystem.public_absence_observed);
    assert!(error.to_string().contains("injected retirement failure"));
    assert!(
        error
            .to_string()
            .contains("new distribution remains published")
    );
    cleanup(&root);
}

#[test]
fn verification_failure_prevents_any_promotion_attempt() {
    let root = temporary_root("verification-before-promotion");
    let final_dist = root.join("dist");
    fs::create_dir_all(&final_dist).expect("create accepted final");
    fs::write(final_dist.join("accepted.txt"), b"accepted").expect("accepted fixture");
    let staging = staged_fixture(&root);
    let mut steps = FakeSteps {
        fail_at: Some("verify"),
        ..FakeSteps::default()
    };

    assert!(execute_transaction(&staging, &final_dist, &mut steps).is_err());
    assert_eq!(
        fs::read(final_dist.join("accepted.txt")).expect("accepted final remains"),
        b"accepted"
    );
    assert!(staging.dist().exists());
    cleanup(&root);
}

fn staged_fixture(root: &Path) -> ReleaseStaging {
    let staging = ReleaseStaging::at(root.join("transactions"), "fixture").expect("staging");
    let artifact = staging.dist().join("cfctl-aarch64-apple-darwin");
    fs::write(artifact, b"unsigned macOS bytes").expect("unsigned fixture");
    staging
}

fn temporary_root(label: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("cfctl-{label}-{}-{unique}", std::process::id()));
    fs::create_dir_all(&root).expect("temporary root");
    root
}

fn cleanup(root: &Path) {
    let _result = fs::remove_dir_all(root);
}
