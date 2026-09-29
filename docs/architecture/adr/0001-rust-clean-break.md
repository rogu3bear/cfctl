# ADR 0001: Rust v2 clean break

- Status: accepted
- Date: 2026-07-14

## Context

The v1 shell runtime accumulated a broad public command surface, backend scripts, and environment-file authentication. That shape cannot provide a stable typed API, crash-safe transactions, platform credential storage, or a complete schema-derived Cloudflare catalog without continuing to multiply parsing and safety paths.

The checkout was already dirty when this work began. Those changes are source intent and must not be reset, stashed, or silently replaced.

## Decision

`cfctl` v2 is a clean public CLI break implemented as a Rust workspace. The versioned public types are `CapabilityV1`, `PlanV1`, `PolicyDecisionV1`, `AgentActionV1`, `EvidenceV1`, and `ResultEnvelopeV2`. Shell scripts are not a public extension surface. Wrangler and cloudflared remain governed subprocess adapters behind catalog capabilities.

Existing desired state and non-secret evidence are imported only by the `migrate v1` command. Credentials are never migrated implicitly. The current v1 launcher and its referenced runtime files are retained in a local, non-release archive for one stable v2 release.

## Consequences

- Existing scripts must move to deterministic v2 commands or explicitly invoke the private compatibility archive.
- The source launcher may build the Rust binary for contributors, but installed releases contain only the native executable.
- Catalog and evidence SQLite files are rebuildable indexes; JSON artifacts remain authoritative.
- The cutover is incomplete until the v2 proof lane and public-contract checks pass.

## Implementation status

The 147-path shell/Python executable estate was hash-bound to the ignored
private archive, audited, and removed. `cargo xtask verify` now rejects any
return of `commands/`, `lib/`, or `scripts/`. The account-backed disposable
token proof moved to `tests/` and requires explicit operator acknowledgement;
all other static proof moved into Rust tests and `xtask`.

The exact behavioral disposition is recorded in
`compat/v1-parity-audit.json` (removed; see Retirement below). Checked-in
v1 desired state and the static v1 catalog were quarantined under `compat/v1/`
during the one-release window. The former remained inert migration input and
the latter non-executable reference data. Neither was a public command
contract.

## Retirement (2026-09-29)

The compatibility window is closed. The `compat/` tree (the v1 parity audit,
the quarantined v1 desired state, and the static v1 catalog), the `migrate v1`
command, the quarantine gates in `cargo xtask verify`, and the documents that
described them (`docs/compat.md`, `docs/v1-parity.md`) were removed on
2026-09-29. The last commit containing them is
`bb61e616c3941c4cb589f12271001057fe7d01e2`, tagged
`archive/cfctl-v1-compat-20260929`. `cargo xtask verify` still rejects any
return of the archived runtime roots, and tracked guidance still may not teach
retired v1 verbs.
