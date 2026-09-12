use super::*;

fn git(repo: &Path, args: &[&str]) {
    assert!(
        StdCommand::new("git")
            .arg("-C")
            .arg(repo)
            .args(args)
            .output()
            .expect("fixture git")
            .status
            .success()
    );
}

#[tokio::test]
async fn completed_import_survives_current_checkout_progress_without_execution_authority() {
    for drift in ["head", "dirty", "deleted"] {
        let (fixture, mut plan) = prepared_import();
        complete_import(&fixture.store, &mut plan, "none");
        let repo = fixture.root.path().join("reviewed");
        match drift {
            "head" => git(
                &repo,
                &["commit", "--allow-empty", "-m", "later source work"],
            ),
            "dirty" => fs::write(repo.join("migration.sql"), "uncommitted later source\n")
                .expect("dirty current source"),
            _ => fs::remove_file(repo.join("migration.sql")).expect("remove current source"),
        }
        let canonical = fixture
            .store
            .load_plan_v2(&plan.operation_id)
            .expect("plan");
        assert!(validate_trusted_root_import_plan(&fixture.store, &canonical).is_err());
        assert!(
            exact_durable_provider_complete_boundary(&fixture.store, &plan.operation_id).is_err()
        );
        let checkpoints = fixture
            .store
            .read_d1_import_checkpoints(&plan.operation_id)
            .expect("history");
        let journal = plan.transaction_journal.clone();
        let result = rectify_loaded_plan(&fixture.store, &mut plan)
            .await
            .expect("completion-only recovery");
        assert!(result.ok, "{drift}");
        assert!(!result.performed);
        assert_eq!(plan.status, PlanStatus::Verified);
        assert_eq!(plan.transaction_stage, TransactionStageV1::Closed);
        assert_eq!(
            &plan.transaction_journal[..journal.len()],
            journal.as_slice()
        );
        assert_eq!(
            fixture
                .store
                .load_plan_v2(&plan.operation_id)
                .expect("closed")
                .pins,
            canonical.pins
        );
        assert_eq!(
            fixture
                .store
                .read_d1_import_checkpoints(&plan.operation_id)
                .expect("history"),
            checkpoints
        );
        let closed = plan.clone();
        assert!(
            rectify_loaded_plan(&fixture.store, &mut plan)
                .await
                .expect("idempotent recovery")
                .ok
        );
        assert_eq!(plan, closed);
    }
}

#[test]
fn historical_completion_rejects_changed_repository_objects_and_private_stage() {
    for drift in [
        "remote",
        "blob",
        "commit",
        "stage",
        "missing_stage",
        "stage_mode",
        "stage_symlink",
    ] {
        let (fixture, mut plan) = prepared_import();
        complete_import(&fixture.store, &mut plan, "none");
        let repo = fixture.root.path().join("reviewed");
        git(
            &repo,
            &["commit", "--allow-empty", "-m", "later source work"],
        );
        let stage = &plan.targets["adapter"]["approved_mln_import"];
        let stage_path = PathBuf::from(stage["stage_path"].as_str().expect("stage path"));
        match drift {
            "remote" => git(
                &repo,
                &[
                    "remote",
                    "set-url",
                    "origin",
                    "https://github.com/other/import.git",
                ],
            ),
            "blob" | "commit" => {
                let field = if drift == "blob" {
                    "git_blob_oid"
                } else {
                    "head"
                };
                let oid = stage["source_authority"][field]
                    .as_str()
                    .expect("original object");
                fs::remove_file(repo.join(".git/objects").join(&oid[..2]).join(&oid[2..]))
                    .expect("remove isolated original loose object");
            }
            "stage" => fs::write(&stage_path, "substituted original bytes").expect("stage tamper"),
            "missing_stage" => fs::remove_file(&stage_path).expect("remove stage"),
            "stage_mode" => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(&stage_path, fs::Permissions::from_mode(0o644))
                        .expect("nonprivate stage");
                }
                #[cfg(not(unix))]
                continue;
            }
            _ => {
                #[cfg(unix)]
                {
                    let preserved = stage_path.with_extension("preserved");
                    fs::rename(&stage_path, &preserved).expect("preserve stage");
                    std::os::unix::fs::symlink(preserved, &stage_path).expect("substitute symlink");
                }
                #[cfg(not(unix))]
                continue;
            }
        }
        let before = plan.clone();
        assert!(
            rectify_completed_reviewed_import(&fixture.store, &mut plan).is_err(),
            "{drift}"
        );
        assert_eq!(plan, before, "{drift}");
        assert_eq!(
            fixture
                .store
                .load_plan(&plan.operation_id)
                .expect("saved state"),
            before
        );
    }
}
