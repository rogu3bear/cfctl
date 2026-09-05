//! Route committed pack identities without loading unrelated execution inputs.
use super::{
    RepositoryNode, Result, WorkspaceError, git_blob, git_repository_root, included_entry,
    register_repository,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};
use walkdir::WalkDir;

// One lookup owns one ephemeral repository list. Selected execution inputs are
// inspected below; no status, pack content or root list survives this call.
pub fn load_workspace_operation_capability(
    roots: &[PathBuf],
    capability_id: &str,
) -> Result<Option<cfctl_core::CapabilityV1>> {
    let candidates = discover(roots)?;
    for loader in [
        super::d1_operation::load_selected,
        super::d1_policy_projection::load_selected,
        super::d1_reply_admission::load_selected,
    ] {
        if let Some(capability) = loader(&candidates, capability_id)? {
            return Ok(Some(capability));
        }
    }
    if let Some(capability) =
        super::reply_subdomain_ingress::load_workspace_reply_subdomain_ingress_capability(
            roots,
            capability_id,
        )?
    {
        return Ok(Some(capability));
    }
    super::d1_evidence::load_selected(&candidates, capability_id)
}

#[cfg(test)]
pub(super) fn repositories(
    roots: &[PathBuf],
    pack: &str,
    capability_id: &str,
) -> Result<Vec<RepositoryNode>> {
    select(&discover(roots)?, pack, capability_id)
}

pub(super) fn select(
    candidates: &[PathBuf],
    pack: &str,
    capability_id: &str,
) -> Result<Vec<RepositoryNode>> {
    let mut selected = BTreeMap::new();
    for repository in candidates {
        if contains(repository, pack, capability_id)? {
            register_repository(repository, &mut selected)?;
        }
    }
    Ok(selected.into_values().collect())
}

pub(super) fn discover(roots: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut seen = BTreeSet::new();
    for root in roots {
        if !root.is_dir() {
            return Err(WorkspaceError::MissingRoot(root.display().to_string()));
        }
        for entry in WalkDir::new(root)
            .follow_links(false)
            .into_iter()
            .filter_entry(included_entry)
            .filter_map(std::result::Result::ok)
        {
            if !entry.file_type().is_dir() || !entry.path().join(".git").exists() {
                continue;
            }
            let repository = git_repository_root(entry.path())?.ok_or_else(|| {
                WorkspaceError::DiscoveryInvariant(format!(
                    "repository marker at `{}` is not backed by a readable Git worktree",
                    entry.path().display()
                ))
            })?;
            seen.insert(repository);
        }
    }
    Ok(seen.into_iter().collect())
}

// Migration, projection, reply-admission and evidence packs share only this
// routing invariant. Their selected execution contracts remain independent.
pub(super) fn contains(repository: &Path, pack: &str, capability_id: &str) -> Result<bool> {
    let Some(bytes) = git_blob(repository, Path::new(pack))? else {
        return Ok(false);
    };
    let invalid = WorkspaceError::DiscoveryInvariant;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| invalid("committed operation pack is not UTF-8".to_owned()))?;
    let value: toml::Value = toml::from_str(text)
        .map_err(|error| invalid(format!("committed operation pack is invalid: {error}")))?;
    Ok(value
        .get("operation")
        .and_then(toml::Value::as_array)
        .is_some_and(|operations| {
            operations.iter().any(|operation| {
                operation.get("id").and_then(toml::Value::as_str) == Some(capability_id)
            })
        }))
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use std::{fs, process::Command};

    const PACK: &str = ".cfctl/operations/d1-evidence.toml";
    const ID: &str = "team.d1-evidence-read";

    fn repository(path: &Path, id: &str) {
        fs::create_dir_all(path.join(".cfctl/operations")).expect("pack directory");
        fs::write(path.join(PACK), format!("[[operation]]\nid = {id:?}\n"))
            .expect("committed pack");
        for args in [
            vec!["init", "-q"],
            vec!["add", "."],
            vec![
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "commit",
                "-qm",
                "fixture",
            ],
        ] {
            assert!(
                Command::new("git")
                    .arg("-C")
                    .arg(path)
                    .args(args)
                    .output()
                    .expect("git")
                    .status
                    .success()
            );
        }
    }

    #[test]
    fn nested_repositories_and_overlapping_roots_preserve_distinct_matches() {
        let root = tempfile::tempdir().expect("root");
        let parent = root.path().join("parent");
        let nested = parent.join("nested");
        repository(&parent, ID);
        repository(&nested, ID);
        let found = repositories(&[root.path().to_path_buf(), nested.clone()], PACK, ID)
            .expect("discover both committed authorities");
        assert_eq!(
            found.len(),
            2,
            "overlap deduplicates paths, never identities"
        );
        assert!(
            found
                .iter()
                .any(|repo| repo.path == nested.canonicalize().expect("nested"))
        );
        assert!(
            found.iter().any(|repo| repo.git.dirty),
            "selected status is inspected"
        );
    }

    #[test]
    fn each_lookup_rediscovers_new_repository_authority() {
        let root = tempfile::tempdir().expect("root");
        let roots = [root.path().to_path_buf()];
        assert!(
            repositories(&roots, PACK, ID)
                .expect("initially absent")
                .is_empty()
        );
        repository(&root.path().join("added"), ID);
        assert_eq!(
            repositories(&roots, PACK, ID).expect("fresh lookup").len(),
            1
        );
    }

    #[test]
    fn worktree_identity_cannot_replace_committed_selection() {
        let root = tempfile::tempdir().expect("root");
        repository(root.path(), ID);
        fs::write(root.path().join(PACK), "[[operation]]\nid = \"other\"\n").expect("dirty pack");
        let roots = [root.path().to_path_buf()];
        let selected = repositories(&roots, PACK, ID).expect("committed identity");
        assert_eq!(selected.len(), 1);
        assert!(selected[0].git.dirty);
        assert!(
            repositories(&roots, PACK, "other")
                .expect("uncommitted ID")
                .is_empty()
        );
    }

    #[test]
    #[cfg(unix)]
    fn nested_symlinks_do_not_expand_registered_authority() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().expect("root");
        let outside = tempfile::tempdir().expect("outside");
        repository(outside.path(), ID);
        symlink(outside.path(), root.path().join("linked")).expect("outside link");
        assert!(
            repositories(&[root.path().to_path_buf()], PACK, ID)
                .expect("no followed link")
                .is_empty()
        );
    }
}
