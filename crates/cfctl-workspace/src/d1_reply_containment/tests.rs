#![allow(clippy::expect_used)] // Fixture setup failures must fail the test.

use std::{fmt::Write as _, fs, path::Path, process::Command};

use cfctl_core::{AdapterStatus, EffectClass, RiskClass};
use tempfile::TempDir;

use super::{PACK_RELATIVE_PATH, declaration::sha256};
use crate::{WorkspaceOperationLoad, inspect_workspace_operation_capability};

fn git(root: &Path, args: &[&str]) {
    let status = Command::new("git")
        .args(args)
        .current_dir(root)
        .status()
        .expect("fixture Git");
    assert!(status.success());
}

fn fixture() -> TempDir {
    let root = tempfile::tempdir().expect("fixture directory");
    git(root.path(), &["init", "-q"]);
    git(root.path(), &["config", "user.name", "Fixture"]);
    git(
        root.path(),
        &["config", "user.email", "fixture@example.invalid"],
    );
    git(root.path(), &["config", "core.hooksPath", "/dev/null"]);
    git(
        root.path(),
        &[
            "remote",
            "add",
            "origin",
            "https://example.invalid/maildesk",
        ],
    );
    fs::create_dir_all(root.path().join(".cfctl/operations")).expect("pack directory");
    fs::create_dir_all(root.path().join("scripts")).expect("compiler directory");
    fs::write(
        root.path().join("scripts/compile-reply-containment.ts"),
        "export {};\n",
    )
    .expect("compiler");
    fs::write(root.path().join("wrangler.toml"), "name = 'fixture'\n").expect("config");
    fs::write(root.path().join(PACK_RELATIVE_PATH), pack()).expect("pack");
    commit(root.path());
    root
}

fn commit(root: &Path) {
    git(root, &["add", "."]);
    git(root, &["commit", "-qm", "fixture"]);
}

fn pack() -> String {
    let mut pack = "schema_version = 1\n".to_owned();
    for (id, tail) in [
        (
            "pre-read",
            "projection = 'maildesk_reply_containment_pre_read_v3'\n",
        ),
        (
            "apply",
            "mutation_projection = 'maildesk_reply_containment_v3'\nperforms_on_call = false\nrecovery_capability_id = 'd1-time-travel-get-bookmark'\nrecovery_max_age_seconds = 600\nrollback_capability_id = 'd1-restore-exact-bookmark'\n",
        ),
        (
            "read",
            "projection = 'maildesk_reply_containment_readback_v3'\nparameters = ['containment_transaction_sha256', 'semantic_bundle_sha256', 'plan_content_hash', 'containment_operation_id']\nauthority_bindings = ['cfctl_build_sha256', 'profile_sha256', 'account_sha256', 'credential_generation_sha256', 'production_database_sha256']\ntransaction_bindings = ['controller_transaction_sha256', 'source_admission_transaction_sha256', 'source_state_sha256', 'correlation_sha256', 'scope_manifest_sha256', 'route_ref_sha256', 'relay_ref_sha256', 'reply_admission_ref_sha256', 'attempt_observation_sha256', 'semantic_bundle_sha256', 'plan_content_hash']\nperformed_requires_exact_match_count = 1\nambiguous_never_proves_containment = true\n",
        ),
    ] {
        write!(pack,
            "\n[[operation]]\nid = 'star-maildesk-cf.reply-containment-{id}'\ntitle = 'Containment'\ndescription = 'Closed fixture'\ncompiler_path = 'scripts/compile-reply-containment.ts'\ncompiler_sha256 = '{}'\ncompiler_runtime = 'bun'\ncompiler_runtime_version = '1.3.14'\ncompiler_runtime_sha256 = 'sha256:{}'\ninput_contract = 'maildesk_reply_containment_v3'\nconfig_template = 'wrangler.toml'\nproduction_config = 'wrangler.production.toml'\ndatabase_binding = 'DB'\nwrangler_version = '4.110.0'\ncaller_sql_allowed = false\nprovider_output_retained = false\nbody_returned = false\n{tail}",
            sha256(b"export {};\n"), "1".repeat(64)
        ).expect("write fixture pack");
    }
    pack
}

#[test]
fn all_three_identities_bind_distinct_closed_lifecycle_contracts() {
    let root = fixture();
    for suffix in ["pre-read", "apply", "read"] {
        let id = format!("star-maildesk-cf.reply-containment-{suffix}");
        let capability = inspect_workspace_operation_capability(&[root.path().into()], &id)
            .expect("load")
            .expect("capability");
        let contract = capability
            .reply_containment_contract()
            .expect("containment contract");
        assert_eq!(contract.operation_kind.capability_id(), id);
        assert!(capability.reply_admission_contract().is_none());
        assert_eq!(capability.adapter_status, AdapterStatus::DelegatedCli);
        assert!(capability.execution_supported);
        assert!(capability.verification_contract_supported());
        if suffix == "apply" {
            assert_eq!(capability.risk, RiskClass::IdentityOrOwnership);
            assert_eq!(capability.effect, EffectClass::IdentityOrOwnership);
        }
    }
}

#[test]
fn inspect_uses_committed_source_but_execution_requires_clean_identity() {
    let root = fixture();
    fs::write(
        root.path().join("scripts/compile-reply-containment.ts"),
        "throw new Error('dirty');\n",
    )
    .expect("dirty compiler");
    let id = "star-maildesk-cf.reply-containment-apply";
    assert!(inspect_workspace_operation_capability(&[root.path().into()], id).is_ok());
    assert!(
        super::load_selected(&[root.path().into()], id, WorkspaceOperationLoad::Execute).is_err()
    );
}

#[test]
fn source_drift_and_unknown_fields_never_fall_back_to_another_carrier() {
    for (from, to) in [
        ("caller_sql_allowed = false", "caller_sql_allowed = true"),
        (
            "wrangler_version = '4.110.0'",
            "wrangler_version = '4.120.1'",
        ),
        (
            "projection = 'maildesk_reply_containment_pre_read_v3'",
            "projection = 'maildesk_reply_admission_read_v1'",
        ),
        (
            "compiler_path = 'scripts/compile-reply-containment.ts'",
            "compiler_path = '../outside.ts'",
        ),
    ] {
        let root = fixture();
        fs::write(
            root.path().join(PACK_RELATIVE_PATH),
            pack().replace(from, to),
        )
        .expect("invalid pack");
        commit(root.path());
        assert!(
            inspect_workspace_operation_capability(
                &[root.path().into()],
                "star-maildesk-cf.reply-containment-apply"
            )
            .is_err()
        );
    }
}

#[test]
fn duplicate_containment_claim_is_rejected_before_binder_selection() {
    let root = fixture();
    let duplicate = "schema_version = 2\ncontract = 'workspace_operation_v1'\n[[operation]]\nid = 'star-maildesk-cf.reply-containment-apply'\n";
    fs::write(
        root.path().join(".cfctl/operations/duplicate.toml"),
        duplicate,
    )
    .expect("duplicate");
    commit(root.path());
    let error = inspect_workspace_operation_capability(
        &[root.path().into()],
        "star-maildesk-cf.reply-containment-apply",
    )
    .expect_err("ambiguous");
    assert!(error.to_string().contains("ambiguous"));
}
