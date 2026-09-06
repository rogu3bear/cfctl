//! By-name coverage for exact ignored agent-facing Markdown paths.
use super::{LOCAL_OPERATOR_ADAPTERS, TaskError, io_error, repository_root};
use std::{fs, path::Path};

// These observational notes receive domain and v1 checks; the command-map
// contract remains specific to the operator adapters.
const LOCAL_AGENT_FACING_NOTES: [&str; 2] = ["NUANCE.md", "WEB.md"];

pub(super) fn paths() -> impl Iterator<Item = &'static str> {
    LOCAL_OPERATOR_ADAPTERS
        .into_iter()
        .chain(LOCAL_AGENT_FACING_NOTES)
}

// Globs remain outside this exact-path inventory. A leading slash anchors an
// ignore rule at the repository root; nested exact paths still need coverage.
// Git ignores unescaped trailing ASCII spaces, but leading whitespace is a name.
fn ignored_markdown_paths(gitignore: &str) -> Vec<&str> {
    gitignore
        .lines()
        .map(|line| line.trim_end_matches(' '))
        .filter(|line| !line.is_empty() && !line.starts_with(['#', '!']))
        .filter(|line| !line.contains(['*', '?', '[']))
        .filter(|line| {
            Path::new(line)
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("md"))
        })
        .map(|line| line.strip_prefix('/').unwrap_or(line))
        .collect()
}

fn check(gitignore: &str) -> Result<(), TaskError> {
    for path in ignored_markdown_paths(gitignore) {
        if !paths().any(|scanned| scanned == path) {
            return Err(TaskError::InvalidSourceContract(format!(
                "{path} is gitignored, so no tracked-file scan reaches it; add its repository-relative path to the local guidance inventory so doctrine gates open it by name"
            )));
        }
    }
    Ok(())
}

pub(super) fn verify() -> Result<(), TaskError> {
    let path = repository_root()?.join(".gitignore");
    let content = fs::read_to_string(&path).map_err(|source| io_error(&path, source))?;
    check(&content)
}

pub(super) fn verify_active_guidance_has_no_v1_commands() -> Result<(), TaskError> {
    let repository_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| {
            TaskError::InvalidSourceContract("xtask has no repository parent".to_owned())
        })?;
    // First-load agent doctrine must not re-teach archived v1 verbs or layout.
    // Historical material below compat/v1 is governed by the quarantine manifest instead.
    // Tracked public guidance and constitutional doctrine are always required.
    // Ignored adapters and notes are present-only but must also stay v2-aligned.
    let required_guidance = [
        "CFCTL_PROMPT.md",
        "docs/agent-landing.md",
        "skills/cfctl-operator/SKILL.md",
        "CONTRIBUTING.md",
        "SECURITY.md",
        "ANCHOR.md",
        "NORTH_STAR.md",
        "LAYERS.md",
    ];
    let stale_v1_guidance = [
        // Archived public verbs / auth lanes
        "./scripts/",
        "--ack-plan",
        "CF_DEV_TOKEN",
        "cfctl surfaces",
        "cfctl ownership",
        "cfctl skills",
        "cloudflare-api-mcp",
        // Archived shell-runtime layout taught as live repo shape
        "lib/runtime/",
        "lib/backends/",
        "`commands/` owns",
        "`commands/` contains",
        "`commands/`: ",
        "`lib/runtime/`",
        "`lib/backends/`",
        "`scripts/`: ",
        "verify_static_contract.sh",
        "verify_public_contract.sh",
        "cfctl standards audit",
        "cfctl admin authorize-backend",
        // Branch or PR lifecycle text must not survive into active guidance.
        "pending merge",
    ];
    for path in required_guidance {
        verify_guidance_file_has_no_stale_v1(repository_root, path, &stale_v1_guidance)?;
    }
    for path in paths() {
        let absolute_path = repository_root.join(path);
        if absolute_path.is_file() {
            verify_guidance_file_has_no_stale_v1(repository_root, path, &stale_v1_guidance)?;
        }
    }
    Ok(())
}

fn verify_guidance_file_has_no_stale_v1(
    repository_root: &Path,
    path: &str,
    stale_v1_guidance: &[&str],
) -> Result<(), TaskError> {
    let absolute_path = repository_root.join(path);
    let content =
        fs::read_to_string(&absolute_path).map_err(|source| io_error(&absolute_path, source))?;
    for phrase in stale_v1_guidance {
        if content.contains(phrase) {
            return Err(TaskError::InvalidSourceContract(format!(
                "{path} still teaches archived v1 guidance `{phrase}`"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::{check, ignored_markdown_paths, verify};
    #[test]
    fn exact_ignored_markdown_paths_include_rooted_and_nested_rules() {
        assert_eq!(
            ignored_markdown_paths(
                "# comment.md\n/AGENTS.md\nNUANCE.md  \n*.local.md\ndocs/private/notes.md\n!KEEP.md\ntarget/\nWEB.md\n"
            ),
            vec!["AGENTS.md", "NUANCE.md", "docs/private/notes.md", "WEB.md"]
        );
    }
    #[test]
    fn unscanned_exact_paths_are_rejected() {
        for path in [
            "PRIVATE_NOTES.md",
            "/PRIVATE_NOTES.md",
            "docs/PRIVATE_NOTES.md",
        ] {
            let error = check(path).expect_err("missing by-name coverage");
            assert!(error.to_string().contains("PRIVATE_NOTES.md"));
        }
    }
    #[test]
    fn leading_space_in_an_ignored_basename_is_significant() {
        let error = check(" AGENTS.md").expect_err("different filename needs coverage");
        assert!(error.to_string().contains(" AGENTS.md is gitignored"));
    }
    #[test]
    fn known_root_anchored_paths_are_covered() {
        check("/AGENTS.md\n/NUANCE.md\n/WEB.md\n").expect("known paths");
    }
    #[test]
    fn repository_exact_ignored_paths_are_covered() {
        verify().expect("current guidance inventory");
    }
}
