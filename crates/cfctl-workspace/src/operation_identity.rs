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

/// Inspect reads the committed pack without requiring a clean worktree.
/// Execute (call/plan/run) keeps the clean-HEAD rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkspaceOperationLoad {
    Inspect,
    Execute,
}

impl WorkspaceOperationLoad {
    #[must_use]
    pub const fn requires_clean_worktree(self) -> bool {
        matches!(self, Self::Execute)
    }
}

// One lookup owns one ephemeral repository list. Selected execution inputs are
// inspected below; no status, pack content or root list survives this call.
pub fn load_workspace_operation_capability(
    roots: &[PathBuf],
    capability_id: &str,
) -> Result<Option<cfctl_core::CapabilityV1>> {
    load_with(roots, capability_id, WorkspaceOperationLoad::Execute)
}

pub fn inspect_workspace_operation_capability(
    roots: &[PathBuf],
    capability_id: &str,
) -> Result<Option<cfctl_core::CapabilityV1>> {
    load_with(roots, capability_id, WorkspaceOperationLoad::Inspect)
}

fn load_with(
    roots: &[PathBuf],
    capability_id: &str,
    mode: WorkspaceOperationLoad,
) -> Result<Option<cfctl_core::CapabilityV1>> {
    load_selected(&discover(roots)?, capability_id, mode)
}

pub(super) fn load_selected(
    candidates: &[PathBuf],
    capability_id: &str,
    mode: WorkspaceOperationLoad,
) -> Result<Option<cfctl_core::CapabilityV1>> {
    let Some(claim) = unique_claim(candidates, capability_id)? else {
        return Ok(None);
    };
    let selected = std::slice::from_ref(&claim.repository);
    let capability = match claim.carrier {
        Carrier::Generic => super::operation_pack::load_selected(selected, capability_id, mode),
        Carrier::Migration => super::d1_operation::load_selected(selected, capability_id, mode),
        Carrier::Qualification => {
            super::d1_qualification::load_selected(selected, capability_id, mode)
        }
        Carrier::Projection => {
            super::d1_policy_projection::load_selected(selected, capability_id, mode)
        }
        Carrier::Reply => super::d1_reply_admission::load_selected(selected, capability_id, mode),
        Carrier::Reads => super::d1_reads::load_selected(selected, capability_id, mode),
        Carrier::Evidence => super::d1_evidence::load_selected(selected, capability_id, mode),
        Carrier::Ingress => {
            super::reply_subdomain_ingress::load_selected(selected, capability_id, mode)
        }
    }?;
    capability.map(Some).ok_or_else(|| WorkspaceError::DiscoveryInvariant(
        "the selected workspace declaration has no supported binding; no alternative owner may replace it".into()
    ))
}

/// Identity-only observation for joining the independent provider catalog.
/// A claim is not proof of supported semantics, clean source or executability.
pub fn workspace_operation_is_claimed(roots: &[PathBuf], capability_id: &str) -> Result<bool> {
    Ok(unique_claim(&discover(roots)?, capability_id)?.is_some())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Carrier {
    Generic,
    Migration,
    Qualification,
    Projection,
    Reply,
    Reads,
    Evidence,
    Ingress,
}
impl Carrier {
    fn typed_pack(path: &Path) -> Option<Self> {
        [
            (super::d1_operation::PACK_RELATIVE_PATH, Self::Migration),
            (
                cfctl_core::workspace_d1::transition::admission::PACK_PATH,
                Self::Qualification,
            ),
            (
                super::d1_policy_projection::PACK_RELATIVE_PATH,
                Self::Projection,
            ),
            (super::d1_reply_admission::PACK_RELATIVE_PATH, Self::Reply),
            (
                cfctl_core::d1_read_inventory::D1_READ_PACK_PATH,
                Self::Reads,
            ),
            (super::d1_evidence::PACK_RELATIVE_PATH, Self::Evidence),
        ]
        .into_iter()
        .find_map(|(name, carrier)| (path == Path::new(name)).then_some(carrier))
    }
}
struct Claim {
    repository: PathBuf,
    pack: PathBuf,
    carrier: Carrier,
}

fn unique_claim(candidates: &[PathBuf], capability_id: &str) -> Result<Option<Claim>> {
    let Some((repository, pack)) =
        super::operation_claims::unique_pack_claim(candidates, capability_id)?
    else {
        return Ok(None);
    };
    let carrier = if pack == Path::new(super::reply_subdomain_ingress::SURFACE_PATH) {
        Carrier::Ingress
    } else {
        let bytes = git_blob(&repository, &pack)?.ok_or_else(|| {
            WorkspaceError::DiscoveryInvariant("selected committed operation disappeared".into())
        })?;
        let text = std::str::from_utf8(&bytes).map_err(|_| {
            WorkspaceError::DiscoveryInvariant("committed operation pack is not UTF-8".into())
        })?;
        let document: toml::Value = toml::from_str(text).map_err(|_| {
            WorkspaceError::DiscoveryInvariant("committed operation pack is invalid TOML".into())
        })?;
        if super::operation_pack::declares_workspace_operation_contract(&document) {
            Carrier::Generic
        } else {
            Carrier::typed_pack(&pack).ok_or_else(|| {
                WorkspaceError::DiscoveryInvariant("selected operation carrier is unsupported".into())
            })?
        }
    };
    Ok(Some(Claim { repository, pack, carrier }))
}

// Explicit linked-checkout and typed source consumers keep their selected scope,
// but their selector cannot waive cross-carrier or in-pack uniqueness.
pub(super) fn unique_typed_owner(
    candidates: &[PathBuf],
    pack: &str,
    id: &str,
) -> Result<Option<PathBuf>> {
    Ok(unique_claim(candidates, id)?
        .filter(|claim| claim.carrier != Carrier::Generic && claim.pack == Path::new(pack))
        .map(|claim| claim.repository))
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
        // A missing registered root must not fail lookup of an unrelated
        // unknown id. WorkspaceGraph::discover still fails closed.
        if !root.is_dir() {
            continue;
        }
        for entry in WalkDir::new(root)
            .follow_links(false)
            .follow_root_links(false)
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
    let count = matching_ids(&pack_document(&bytes)?, capability_id);
    if count > 1 {
        return Err(WorkspaceError::DiscoveryInvariant(
            "workspace operation id is ambiguous within its committed pack".into(),
        ));
    }
    Ok(count == 1)
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
    fn missing_registered_root_does_not_poison_unknown_capability_lookup() {
        let roots = [PathBuf::from("/this/registered/root/does-not-exist")];
        assert!(
            load_workspace_operation_capability(&roots, "definitely.not-a-capability")
                .expect("missing root is not an unknown-id failure")
                .is_none()
        );
        assert!(
            inspect_workspace_operation_capability(&roots, "definitely.not-a-capability")
                .expect("missing root is not an inspect failure")
                .is_none()
        );
    }

    #[test]
    fn missing_root_is_skipped_during_operation_discovery() {
        let root = tempfile::tempdir().expect("root");
        repository(root.path(), ID);
        let missing = root.path().join("missing");
        let found = discover(&[missing, root.path().to_path_buf()]).expect("skip missing");
        assert_eq!(found.len(), 1);
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
