# Command-language acceptance criteria

## Outcome

A user can read the cfctl command language once, understand its stable shape,
find every deterministic operation, and recover from an invalid invocation
without learning an internal module or maintaining a second command registry.

The observable grammar is:

```text
cfctl <area> <action> [target] [flags]
```

The area stays first and the action says what happens. Direct operations such
as `resolve`, `guide`, and `call` omit the area. Natural-language input remains
the quoted `cfctl "<request>"` lane. Existing v2 paths remain compatible.

## Canonical owners and denominator

| Surface | Canonical owner | Observable check |
| --- | --- | --- |
| Operation names, nesting, arguments, aliases, and help | `cfctl-cli` Clap tree | `cfctl commands`, `cfctl <path> --help` |
| Compatibility inventory | `cfctl-core::PUBLIC_V2_SUBCOMMANDS` and `PUBLIC_V2_COMMAND_TREE` | recursive Clap-contract tests |
| Runtime behavior | `cfctl-cli::runtime` dispatch | compiler-exhaustive match and runtime tests |
| Capability operations and adapters | executable capability catalog | `catalog`, `resolve`, and `guide`; never duplicated into the command map |
| Failure reasons and recovery | Clap parse errors and `CliError` | nonzero exit, exact reason, nearest help or complete-map next step |
| Human documentation | README, quickstart, runbook, and managed agent guidance | examples validated by repository-native verification |

The acceptance denominator is every node in the built Clap tree: groups and
leaf operations at every depth, excluding Clap's generated `help` nodes. On
the candidate that introduced this contract, that is 108 deterministic paths.
The number may grow; completeness, nonblank summaries, stable grammar, precise
failure guidance, and compatibility are the invariant—not a frozen count.

Aliases are projected explicitly. The baseline has no custom aliases, and this
change adds none: a second spelling would be another memory burden unless a
specific compatibility requirement justified it.

The capability denominator is every entry in the executable catalog, exhausted
by the catalog owner's five adapter statuses. The command map projects this
status-to-grammar matrix without copying capability IDs:

| Adapter status | Canonical invocation | Observable result |
| --- | --- | --- |
| `native` | `cfctl call <capability-id>` | run the cfctl-owned adapter or draft its governed mutation plan |
| `dynamic_api` | `cfctl call <capability-id>` | run the catalog-bound API read or draft its governed mutation plan |
| `delegated_cli` | `cfctl call <capability-id>` | run the catalog-pinned CLI and retain its bounded receipt |
| `governed_ui` | `cfctl call <capability-id>` | return the target-bound UI handoff without widening authority |
| `blocked` | `cfctl guide <capability-id>` | stop at the exact blocker and follow `next_action`; `call` remains fail-closed |

Every row uses `resolve` for intent discovery, `catalog show` for the executable
contract, and `guide` for selectors, lifecycle, blockers, and next action.

## Acceptance criteria

### AC1 — One exhaustive map

Given the built cfctl binary, when a user runs `cfctl commands`, then one human
view lists every deterministic group and leaf path at every nesting depth with
a nonblank purpose, plus the stable grammar and memorable starting paths.

Given the same binary, when a program runs `cfctl commands --json`, then a
successful `ResultEnvelopeV2` contains the same paths, summaries, kinds, and
aliases without opening or changing mutable runtime state.

### AC2 — Help is locally discoverable

Given root help, when a user reads the root help screen, then it points to
`cfctl commands` for the whole language.

Given any command group, when a user runs `cfctl <path> --help`, then every
direct child has a nonblank description and the exact local usage is shown.

### AC3 — Failure is actionable

Given an invalid human invocation, when Clap rejects it, then cfctl preserves
Clap's exact reason, usage, suggestion, and nonzero exit behavior.

Given an invalid `--json` invocation, when parsing fails, then the
`CFCTL_USAGE` envelope preserves the exact rejection and directs the caller to
the nearest command help and `cfctl commands` rather than a generic retry.

### AC4 — Compatibility is preserved

Given any pre-existing v2 command path, when the candidate is parsed or run,
then its name, nesting, arguments, dispatch, authorization boundary, output
contract, and behavior remain unchanged. `cfctl commands` is additive.

Given an unknown bare token or a retired v1 shape, when it is invoked, then it
still fails closed through the deterministic parser instead of launching the
agent lane.

### AC5 — No parallel authority

Given a command is added, removed, renamed, nested, or aliased in Clap, when
tests run, then the compatibility inventory must change with it and the
generated command map reflects it automatically. No hand-maintained command
list may claim to be exhaustive.

Given a catalog capability is added or changed, when the command map is built,
then the catalog remains its owner; the map describes only the stable `call`,
`resolve`, `guide`, and catalog-management paths.

Given any capability in any current adapter status, when a user reads the
catalog-to-grammar matrix, then there is exactly one canonical discovery,
inspection, explanation, and invocation route, with blocked capabilities
stopping at their exact `next_action`.

### AC6 — Qualification stays plane-specific

Given the exact committed source candidate, when repository-native verification
passes, then the claim is limited to source, help, parsing, tests, and local
build behavior. Unsigned assembly, signing, publication, deployment, provider
state, and user adoption remain separate evidence planes.

## Exclusions

This change does not rename commands, invent shorthand aliases, change runtime
dispatch, broaden mutation authority, sign or publish artifacts, deploy cfctl,
or claim that local usability proof establishes user adoption.
