# v1 behavioral-parity and shell-removal audit

The Rust v2 cutover removes the tracked v1 executable estate without claiming
flag-for-flag compatibility. The reviewed estate contained 147 paths: one
shell command, 19 shell runtime/backend files, and 127 scripts. Of those, 140
were shell and seven were Python.

Every removed path is present in the local compatibility archive
`.cfctl-private-archive/v1-shell-2026-07-14/runtime.tar.gz`, whose SHA-256 is
`10c8b5fe9d0e9a98c7d97fe9fe28d320d470785207a565ff080188225e626dcb`.
That is local proof, not a public release artifact. The archive is gitignored,
contains the adopted dirty source intent, and is not an executable fallback.

The machine-readable audit is
[`compat/v1-parity-audit.json`](../compat/v1-parity-audit.json). It binds the
archive hashes, path counts, behavioral disposition, and the small set of
non-public shell entrypoints that remain for source bootstrap, packaging, and
explicit account smoke proof.

## Behavioral disposition

| v1 behavior | v2 disposition |
| --- | --- |
| inventory scripts and `list/get/snapshot/verify` | Expanded into the schema-derived catalog, `guide`, and `call` |
| mutation scripts and `apply` | Strengthened into hash-bound plans, exact approval, durable execution, operation-specific verification, and separate rectification |
| token mint/rotate/revoke | Strengthened into native `keys` commands with sink-only secrets and live readback |
| previews and locks | Replaced by durable `plans show/status/resume/rectify` state |
| ownership, standards, and diff | Expanded into registered-root discovery, dependency graphs, IaC audits, and plan-bound diffs |
| Wrangler and cloudflared wrappers | Replaced by cataloged delegated-CLI capabilities with cleared environments and evidence receipts |
| hostname, maildesk-cf, and form-intake composites | Decomposed into workspace dependencies, catalog capabilities, guides, and plans |
| arbitrary `env run` | Retired; only cataloged delegated subprocesses receive a selected credential |
| backend bypass authorization | Retired; v2 has no shell mutation backend to bypass into |

This is not “green by deletion.” Generated writes remain visibly blocked when
risk, cost, entitlement, permissions, verification, or compensation is
incomplete. The audit records deliberate decompositions and security
retirements instead of pretending every v1 flag survived.

## Enforced boundary

`cargo xtask verify` fails if `commands/`, `lib/`, or `scripts/` reappears. The
static proof itself now runs in Rust, and the isolated CLI test proves doctor,
registered-root handling, and v2 envelope shape without relying on v1 code.
The account-backed disposable token lifecycle remains
[`tests/account-backed-smoke.sh`](../tests/account-backed-smoke.sh); it requires
an existing selected profile plus an explicit acknowledgement and performs its
own revoke compensation.

The checked-in `state/` tree is inert desired-state input for the compatibility
window. `cfctl migrate v1` copies only safe desired state and evidence into
content-addressed imports and never imports credentials. The checked-in static
v1 `catalog/` is non-executable reference data and is not loaded by Rust v2.
