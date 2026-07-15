# cfctl v2 operator runbook

## Health and discovery

```bash
cfctl doctor --json
cfctl catalog sync --json
cfctl catalog coverage --json
cfctl docs changes --json
cfctl agents doctor --json
```

Use `mutation_contract_gap_counts` to distinguish unknown risk, effect, cost,
verification, rollback, permissions, and entitlement debt. Counts overlap;
`capabilities_with_mutation_contract_gaps` counts affected operations once,
while `blocked_adapters_without_contract_gaps` identifies separate adapter or
workflow blockers.

Find and inspect an operation:

```bash
cfctl catalog search "<intent>" --json
cfctl catalog show <capability-id> --json
cfctl guide <capability-id> --json
```

Treat the guide as an executable safety contract, not prose. Run `call_argv`
only when `contract_state` is `available`. When it is `blocked`, resolve every
named `blocking_gaps` entry through the supplied safe `next_action`; the
`post_resolution_call_argv` field is a template and is deliberately not an
execution recommendation. It is `null` when no safe future execution surface
exists. Commands are argv arrays so agents never have to guess shell quoting.

## Authentication

Normal OAuth login uses a public client and PKCE:

```bash
cfctl auth login --profile default --client-id <client-id> \
  --scope <scope-id> --account <account-id> --json
```

Open the returned authorization URL, then pipe the callback's one-time
`STATE CODE` value into the same command with `--complete`. Use `auth status`,
`profiles`, `use`, and `logout` for profile lifecycle. Import an emergency
global key only through stdin; cfctl never selects it silently.

## Workspace boundaries

```bash
cfctl workspace add /absolute/root --account <account-id> --json
cfctl workspace discover --json
cfctl workspace graph --json
cfctl workspace audit --json
```

Only registered roots are scanned. Fix account ambiguity or dirty overlap
before planning writes.

## Reads

```bash
cfctl call <capability-id> \
  --selector account_id=<account-id> \
  --query per_page=100 --json
```

The typed transport validates selectors and bodies against the pinned schema,
paginates, backs off on rate limits, uses conditionals when supplied, and emits
structured Cloudflare errors.

## Writes

`call` creates a plan for a mutating capability. Review it, then:

```bash
cfctl plans show <operation-id> --json
cfctl plans approve <operation-id> --yes --json
cfctl plans run <operation-id> --json
cfctl plans status <operation-id> --json
```

Use `--max-cost CURRENCY:AMOUNT` for paid plans. Use `plans resume` only for a
draft or approved plan; consumed/running plans are deliberately non-replayable.
Use `plans rectify` to inspect compensation and verification steps after an
uncertain or unsupported result.

Secret outputs require `--value-out /new/secure/path`; cfctl refuses an
existing destination.

Mint an account token only through the dedicated key workflow:

```bash
cfctl keys permissions --account <account-id> --json
cfctl keys mint --name <name> --permission <reviewed-group-id> \
  --account <account-id> --ttl-hours <hours> \
  --value-out /new/secure/path --json
```

Mint planning repeats the live permission inventory and binds the exact group
metadata and account-only resource policy. Running the approved plan repeats
that inventory read before consumption; drift requires a new plan. Do not use
generic `call` for token creation.

## Agent entry

```bash
cfctl agents install --all-detected --json
cfctl agents doctor --json
cfctl "<natural-language Cloudflare request>"
```

Natural language launches one configured local agent. The agent must translate
intent to deterministic commands; it cannot approve or directly mutate state.

## Local proof

```bash
cargo xtask verify
```

Do not report completion without the applicable source-config, live-read,
preview, apply, and post-change verification evidence.
