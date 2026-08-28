//! Human and structured projections of the executable Clap command tree.

use std::fmt::Write as _;

use cfctl_core::{AdapterStatus, ResultEnvelopeV2};
use clap::{CommandFactory as _, builder::StyledStr};
use serde_json::{Value, json};

use crate::Cli;

const GRAMMAR: &str = "cfctl <area> <action> [target] [flags]";

const STARTING_PATHS: &[(&str, &str)] = &[
    (
        "cfctl \"<natural-language request>\"",
        "hand an open-ended request to the configured local agent",
    ),
    (
        "cfctl resolve \"<intent>\"",
        "map intent to one deterministic catalog capability",
    ),
    (
        "cfctl guide <capability-id>",
        "learn the exact governed lifecycle before acting",
    ),
    (
        "cfctl call <capability-id>",
        "read live state or draft a mutation plan",
    ),
    (
        "cfctl plans show|approve|run|status <operation-id>",
        "review and advance the durable mutation lifecycle",
    ),
];

pub(crate) fn envelope() -> ResultEnvelopeV2 {
    let mut root = Cli::command();
    root.build();
    let commands = command_entries(&root);
    let catalog_routes = catalog_routes();
    let message = render_human(&commands, &catalog_routes);
    ResultEnvelopeV2::success(
        "commands",
        json!({
            "schema_version": 1,
            "grammar": GRAMMAR,
            "starting_paths": STARTING_PATHS
                .iter()
                .map(|(command, purpose)| json!({ "command": command, "purpose": purpose }))
                .collect::<Vec<_>>(),
            "commands": commands,
            "catalog_routes": catalog_routes,
            "message": message,
        }),
    )
}

fn catalog_routes() -> Vec<Value> {
    AdapterStatus::ALL
        .iter()
        .map(|status| {
            let (invoke, result) = catalog_route(*status);
            json!({
                "adapter_status": status,
                "discover": "cfctl resolve \"<intent>\"",
                "inspect": "cfctl catalog show <capability-id>",
                "explain": "cfctl guide <capability-id>",
                "invoke": invoke,
                "result": result,
            })
        })
        .collect()
}

fn catalog_route(status: AdapterStatus) -> (&'static str, &'static str) {
    match status {
        AdapterStatus::Native => (
            "cfctl call <capability-id>",
            "run the cfctl-owned native adapter or draft its governed mutation plan",
        ),
        AdapterStatus::DynamicApi => (
            "cfctl call <capability-id>",
            "run the catalog-bound API read or draft its governed mutation plan",
        ),
        AdapterStatus::DelegatedCli => (
            "cfctl call <capability-id>",
            "run the catalog-pinned delegated CLI and preserve its bounded receipt",
        ),
        AdapterStatus::GovernedUi => (
            "cfctl call <capability-id>",
            "return the target-bound governed UI handoff without widening authority",
        ),
        AdapterStatus::Blocked => (
            "cfctl guide <capability-id>",
            "stop at the exact blocker and follow next_action; call remains fail-closed",
        ),
    }
}

fn command_entries(root: &clap::Command) -> Vec<Value> {
    let mut entries = Vec::new();
    collect_entries(root, "cfctl", &mut entries);
    entries
}

fn collect_entries(parent: &clap::Command, parent_path: &str, entries: &mut Vec<Value>) {
    for command in parent
        .get_subcommands()
        .filter(|command| command.get_name() != "help")
    {
        let path = format!("{parent_path} {}", command.get_name());
        let summary = command
            .get_about()
            .map(StyledStr::to_string)
            .unwrap_or_default();
        let aliases = command.get_all_aliases().collect::<Vec<_>>();
        let has_subcommands = command
            .get_subcommands()
            .any(|child| child.get_name() != "help");
        entries.push(json!({
            "path": path,
            "summary": summary,
            "aliases": aliases,
            "kind": if has_subcommands { "group" } else { "operation" },
        }));
        collect_entries(command, &path, entries);
    }
}

fn render_human(commands: &[Value], catalog_routes: &[Value]) -> String {
    let mut output = String::from("cfctl command language\n\n");
    let _ = writeln!(output, "Grammar: {GRAMMAR}");
    output.push_str("The area stays first; the action says what happens. Direct operations such as `resolve`, `guide`, and `call` omit the area. Existing paths remain compatible.\n\nStart here:\n");
    for (command, purpose) in STARTING_PATHS {
        let _ = writeln!(output, "  {command:<58} {purpose}");
    }
    output.push_str("\nEvery catalog capability uses the same grammar:\n");
    for route in catalog_routes {
        let Some(status) = route.get("adapter_status").and_then(Value::as_str) else {
            continue;
        };
        let Some(invoke) = route.get("invoke").and_then(Value::as_str) else {
            continue;
        };
        let Some(result) = route.get("result").and_then(Value::as_str) else {
            continue;
        };
        let _ = writeln!(output, "  {status:<14} {invoke:<37} {result}");
    }
    output.push_str("  All statuses: resolve intent, inspect with catalog show, and explain with guide before invocation.\n");
    output.push_str("\nComplete deterministic map:\n");
    for entry in commands {
        let Some(path) = entry.get("path").and_then(Value::as_str) else {
            continue;
        };
        let Some(summary) = entry.get("summary").and_then(Value::as_str) else {
            continue;
        };
        let depth = path.split_whitespace().count().saturating_sub(2);
        let indent = "  ".repeat(depth + 1);
        let display_path = path.strip_prefix("cfctl ").unwrap_or(path);
        let _ = writeln!(output, "{indent}{display_path:<42} {summary}");
    }
    output.push_str(
        "\nDetails: cfctl <command path> --help\nMachine-readable map: cfctl commands --json\n",
    );
    output
}

#[cfg(test)]
mod tests {
    use super::{catalog_routes, command_entries, render_human};
    use crate::Cli;
    use clap::CommandFactory as _;

    #[test]
    fn every_projected_command_has_a_summary() {
        let mut root = Cli::command();
        root.build();
        let commands = command_entries(&root);
        let missing = commands
            .iter()
            .filter_map(|entry| {
                entry["summary"]
                    .as_str()
                    .filter(|summary| summary.is_empty())
                    .and_then(|_| entry["path"].as_str())
            })
            .collect::<Vec<_>>();
        assert!(
            missing.is_empty(),
            "commands without help summaries: {missing:?}"
        );
    }

    #[test]
    fn human_projection_contains_every_executable_path() {
        let mut root = Cli::command();
        root.build();
        let commands = command_entries(&root);
        let rendered = render_human(&commands, &catalog_routes());
        for entry in commands {
            let Some(path) = entry["path"].as_str() else {
                panic!("projected entry has no command path: {entry}");
            };
            let path = path.trim_start_matches("cfctl ");
            assert!(rendered.contains(path), "missing command path `{path}`");
        }
    }

    #[test]
    fn catalog_matrix_covers_every_adapter_status_once() {
        let routes = catalog_routes();
        assert_eq!(routes.len(), cfctl_core::AdapterStatus::ALL.len());
        let statuses = routes
            .iter()
            .filter_map(|route| route["adapter_status"].as_str())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(statuses.len(), cfctl_core::AdapterStatus::ALL.len());
        assert!(routes.iter().all(|route| {
            ["discover", "inspect", "explain", "invoke", "result"]
                .iter()
                .all(|field| {
                    route[*field]
                        .as_str()
                        .is_some_and(|value| !value.is_empty())
                })
        }));
    }
}
