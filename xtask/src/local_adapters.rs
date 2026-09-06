//! Keep local adapters pointing to the generated parser command map.
use super::{TaskError, io_error, repository_root};
use clap::CommandFactory as _;
use std::fs;

/// Local operator adapters. `LAYERS.md` keeps these gitignored so a clone
/// inherits the constitution without an operator context, which also puts them
/// outside `git ls-files` and therefore outside every tracked-file scan. Source
/// contracts that guard doctrine must check them explicitly or leave a blind
/// spot: the retired public domain survived in `AGENTS.md` for exactly that
/// reason. Present-only — a clone legitimately has neither.
pub(super) const LOCAL_OPERATOR_ADAPTERS: [&str; 2] = ["AGENTS.md", "CLAUDE.md"];

pub(super) fn verify() -> Result<(), TaskError> {
    let root = repository_root()?;
    for path in LOCAL_OPERATOR_ADAPTERS {
        let absolute = root.join(path);
        if !absolute.is_file() {
            continue;
        }
        let content =
            fs::read_to_string(&absolute).map_err(|source| io_error(&absolute, source))?;
        if let Some(line) = enumerated_command_line(&content) {
            return Err(TaskError::InvalidSourceContract(format!(
                "{path} enumerates the command surface (`{line}`). Point at `cfctl commands` instead of maintaining a second map."
            )));
        }
    }
    Ok(())
}

fn enumerated_command_line(content: &str) -> Option<&str> {
    let parser = cfctl_cli::Cli::command();
    content.lines().map(str::trim).find(|line| {
        line.split('`').any(|fragment| {
            let tokens: Vec<_> = fragment.split_whitespace().collect();
            let Some(start) = tokens
                .iter()
                .position(|token| matches!(*token, "cfctl" | "./cfctl"))
            else {
                return false;
            };
            let mut node = &parser;
            for token in tokens.into_iter().skip(start + 1) {
                if token == "--json" {
                    continue;
                }
                if token.starts_with('-') || !node.has_subcommands() {
                    break;
                }
                // Known alternatives at a command position form a verb inventory.
                // Other words may be external commands in a compact shell pipeline.
                if token.contains('|')
                    && token
                        .split('|')
                        .all(|part| !part.is_empty() && node.find_subcommand(part).is_some())
                {
                    return true;
                }
                let Some(child) = node.find_subcommand(token) else {
                    break;
                };
                node = child;
            }
            false
        })
    })
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::{enumerated_command_line, verify};
    #[test]
    fn local_adapters_defer_to_the_generated_map() {
        verify().expect("local adapters");
    }
    #[test]
    fn detects_known_maps_in_both_public_spellings_and_markdown() {
        for source in [
            "cfctl catalog sync|search|show",
            "./cfctl catalog sync|search|show",
            "Use `cfctl catalog sync|search|show` to discover commands.",
            "- `./cfctl auth evidence-key init|status|rotate`",
            "cfctl --json catalog sync|search",
        ] {
            assert!(enumerated_command_line(source).is_some(), "{source}");
        }
    }
    #[test]
    fn accepts_shell_operators_leaf_arguments_and_flag_values() {
        for source in [
            "cfctl commands",
            "cfctl commands --json",
            "cfctl commands | cat",
            "cfctl commands|cat",
            "cfctl doctor || exit 1",
            "cfctl catalog sync | cat",
            "cfctl catalog sync|cat",
            "cfctl guide --topic a|b",
            "cfctl resolve dns|workers",
            "cfctl catalog search dns|workers",
        ] {
            assert!(enumerated_command_line(source).is_none(), "{source}");
        }
    }
}
