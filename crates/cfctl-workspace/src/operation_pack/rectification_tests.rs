//! Committed identity and declaration regressions, through the public loaders.
#![allow(clippy::expect_used)] // Fixture setup failures must fail the test.
use super::tests::{V2_EVIDENCE, fixture, fixture_named};
use crate::{inspect_workspace_operation_capability, load_workspace_operation_capability};
use std::{fs, path::Path, process::Command};

const ID: &str = "star-maildesk-cf.d1-evidence-read";
const EVIDENCE: &str = ".cfctl/operations/d1-evidence.toml";
fn supported() -> String {
    V2_EVIDENCE.replace("columns = [\"active_policy_digest\"]", "columns = []")
}
fn commit(root: &Path) {
    for args in [
        ["add", "."].as_slice(),
        ["commit", "-qm", "updated fixture"].as_slice(),
    ] {
        let result = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .expect("git");
        assert!(result.status.success());
    }
}
fn claim(root: &Path, path: &str, text: &str) {
    let path = root.join(path);
    fs::create_dir_all(path.parent().expect("parent")).expect("parent");
    fs::write(path, text).expect("claim");
}
fn ambiguous(roots: &[std::path::PathBuf]) {
    let error = inspect_workspace_operation_capability(roots, ID).expect_err("ambiguous identity");
    assert!(
        error.to_string().contains("ambiguous"),
        "identity must be resolved before binding: {error}"
    );
}

#[test]
fn ownership_refuses_duplicate_generic_ids_before_binding() {
    let pack = supported();
    let duplicate = format!(
        "{pack}\n[[operation]]{}",
        pack.split_once("[[operation]]").expect("operation").1
    );
    let root = fixture(&duplicate);
    ambiguous(&[root.path().to_path_buf()]);
}

#[test]
fn ownership_refuses_duplicate_ids_in_every_typed_carrier_before_execution_inputs() {
    for pack in [
        "d1-migrations.toml",
        "d1-policy-projections.toml",
        "d1-reply-admission.toml",
        "d1-evidence.toml",
        "d1-reads.toml",
        "d1-transition-qualification.toml",
    ] {
        let declaration =
            format!("schema_version = 1\n[[operation]]\nid = {ID:?}\n[[operation]]\nid = {ID:?}\n");
        let root = fixture_named(&format!(".cfctl/operations/{pack}"), &declaration);
        ambiguous(&[root.path().to_path_buf()]);
    }
}

#[test]
fn ownership_counts_generic_typed_and_cross_repository_claims_without_binding_them() {
    let pack = supported();
    for competing in [
        "generic.toml",
        "d1-migrations.toml",
        "d1-policy-projections.toml",
        "d1-reply-admission.toml",
        "d1-reads.toml",
        "d1-transition-qualification.toml",
    ] {
        let root = fixture(&pack);
        let declaration = if competing == "generic.toml" {
            pack.clone()
        } else {
            format!("schema_version = 1\n[[operation]]\nid = {ID:?}\n")
        };
        claim(
            root.path(),
            &format!(".cfctl/operations/{competing}"),
            &declaration,
        );
        commit(root.path());
        // Even an unsupported/incomplete selected competitor is an identity
        // claim. Its missing private execution inputs cannot erase it.
        ambiguous(&[root.path().to_path_buf()]);
    }
    let generic = fixture(&pack);
    let typed = fixture_named(
        ".cfctl/operations/d1-migrations.toml",
        &format!("schema_version = 1\n[[operation]]\nid = {ID:?}\n"),
    );
    ambiguous(&[generic.path().to_path_buf(), typed.path().to_path_buf()]);
    let first_typed = fixture_named(
        EVIDENCE,
        &format!("schema_version = 1\n[[operation]]\nid = {ID:?}\n"),
    );
    claim(
        first_typed.path(),
        ".cfctl/operations/d1-policy-projections.toml",
        &format!("schema_version = 1\n[[operation]]\nid = {ID:?}\n"),
    );
    commit(first_typed.path());
    ambiguous(&[first_typed.path().to_path_buf()]);
}

#[test]
fn ownership_keeps_overlapping_roots_and_committed_inspection_distinct_from_execution() {
    let root = fixture(&supported());
    let roots = [
        root.path().to_path_buf(),
        root.path().canonicalize().expect("canonical"),
    ];
    assert!(
        inspect_workspace_operation_capability(&roots, ID)
            .expect("deduplicated")
            .is_some()
    );
    fs::write(
        root.path().join("unrelated.txt"),
        "dirty unrelated application work",
    )
    .expect("dirty");
    assert!(
        inspect_workspace_operation_capability(&roots, ID)
            .expect("committed inspection")
            .is_some()
    );
    assert!(load_workspace_operation_capability(&roots, ID).is_err());
    assert!(
        inspect_workspace_operation_capability(&roots, "not.claimed")
            .expect("unknown ignores unrelated dirty work")
            .is_none()
    );
}

#[test]
fn ownership_selected_unsupported_generic_declaration_never_disappears() {
    let root = fixture(&supported().replace("adapter = \"d1\"", "adapter = \"unimplemented\""));
    assert!(inspect_workspace_operation_capability(&[root.path().to_path_buf()], ID).is_err());
    let root = fixture(&supported().replace("schema_version = 2", "schema_version = 99"));
    assert!(inspect_workspace_operation_capability(&[root.path().to_path_buf()], ID).is_err());
}

#[cfg(unix)]
#[test]
fn ownership_does_not_expand_through_registered_or_nested_symlink_aliases() {
    let root = tempfile::tempdir().expect("root");
    let outside = fixture(&supported());
    let alias = root.path().join("alias");
    std::os::unix::fs::symlink(outside.path(), &alias).expect("alias");
    for path in [root.path(), alias.as_path()] {
        assert!(
            inspect_workspace_operation_capability(&[path.to_path_buf()], ID)
                .expect("alias cannot register source")
                .is_none()
        );
    }
}

#[test]
fn declarations_refuse_known_but_unsupported_or_conflicting_semantics() {
    let valid = supported();
    let variants = [
        valid.replace("performs_on_call = true", "performs_on_call = false"),
        valid.replace("performs_on_call = true", "performs_on_call = true\ntables = [\"only_this_table\"]"),
        valid.replace("[operation.verification]", "[[operation.input]]\nname = \"caller_sql\"\ntype = \"string\"\nrequired = true\n[operation.verification]"),
        valid.replace("strategy = \"row_shape\"", "strategy = \"row_shape\"\n[[operation.verification.digest]]\nkey = \"claimed\"\nsource = \"input:value\""),
        valid.replace("columns = []", "columns = [\"active_policy_digest\"]"),
        valid.replace("columns = []", "columns = []\nraw_digest_columns = [\"active_policy_digest\"]"),
        format!("{valid}\n[operation.evidence]\nadapter = \"invented\"\nrequired_keys = [\"claimed\"]\nexact_keys = true\n"),
        format!("{valid}\n[operation.compensation]\nrecovery_capability_id = \"d1-time-travel-get-bookmark\"\n"),
    ];
    for (index, pack) in variants.into_iter().enumerate() {
        let root = fixture(&pack);
        assert!(
            inspect_workspace_operation_capability(&[root.path().to_path_buf()], ID).is_err(),
            "ignored known semantic field {index} was accepted"
        );
    }
}

#[test]
fn declarations_enforce_exact_columns_and_the_fixed_default_tool() {
    let columns = crate::MAILDESK_D1_EVIDENCE_COLUMNS_V1
        .iter()
        .chain(crate::MAILDESK_D1_POLICY_IDENTITY_COLUMNS_V2)
        .chain(crate::MAILDESK_D1_ROUTE_HEALTH_COLUMNS_V2)
        .copied()
        .collect::<Vec<_>>();
    let complete = supported().replace("columns = []", &format!("columns = {columns:?}"));
    for declaration in [
        supported(),
        complete.clone(),
        supported().replace("tool = \"wrangler\"\n", ""),
    ] {
        let root = fixture(&declaration);
        let cap = load_workspace_operation_capability(&[root.path().to_path_buf()], ID)
            .expect("supported")
            .expect("claim");
        assert!(!cap.mutating);
        let source = cap.workspace_d1_evidence.expect("typed source");
        assert_eq!(source.database_binding, "DB");
        assert_eq!(source.wrangler_version, "4.120.1");
        assert_eq!(source.projection, "maildesk_v1");
    }
    for declaration in [
        complete.replace(
            "active_policy_digest\",",
            "active_policy_digest\", \"active_policy_digest\",",
        ),
        supported().replace("tool = \"wrangler\"", "tool = \"arbitrary\""),
        supported().replace("tool_version = \"4.120.1\"", "tool_version = \"latest\""),
        supported().replace(
            "config_template = \"wrangler.toml\"",
            "config_template = \"../outside.toml\"",
        ),
        supported().replace(
            "production_config = \"wrangler.production.toml\"",
            "production_config = \"../outside.toml\"",
        ),
        supported().replace(
            "database_binding = \"DB\"",
            "database_binding = \"bad binding\"",
        ),
        supported().replace("mutates = false", "mutates = true"),
        supported().replace("strategy = \"row_shape\"", "strategy = \"assertion_rows\""),
        supported().replace(
            "strategy = \"row_shape\"",
            "strategy = \"cardinality_digest\"",
        ),
        format!(
            "{}\n[operation.compiler]\npath = \"unreviewed.ts\"\n",
            supported()
        ),
    ] {
        let root = fixture(&declaration);
        assert!(inspect_workspace_operation_capability(&[root.path().to_path_buf()], ID).is_err());
    }
}
