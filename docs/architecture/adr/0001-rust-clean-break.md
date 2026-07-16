# ADR 0001: Rust v2 clean break

- Status: accepted
- Date: 2026-07-14

## Context

The v1 shell runtime accumulated a broad public command surface, backend scripts, and environment-file authentication. That shape cannot provide a stable typed API, crash-safe transactions, platform credential storage, or a complete schema-derived Cloudflare catalog without continuing to multiply parsing and safety paths.

The checkout was already dirty when this work began. Those changes are source intent and must not be reset, stashed, or silently replaced.

## Decision

`cfctl` v2 is a clean public CLI break implemented as a Rust workspace. The versioned public types are `CapabilityV1`, `PlanV1`, `PolicyDecisionV1`, `AgentActionV1`, `EvidenceV1`, and `ResultEnvelopeV2`. Shell scripts are not a public extension surface. Wrangler and cloudflared remain governed subprocess adapters behind catalog capabilities.

Existing desired state and non-secret evidence are imported only by `cfctl migrate v1`. Credentials are never migrated implicitly. The current v1 launcher and its referenced runtime files are retained in a local, non-release archive for one stable v2 release.

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
[`compat/v1-parity-audit.json`](../../../compat/v1-parity-audit.json). Checked-in
v1 desired state and the static v1 catalog are quarantined under `compat/v1/`
during the one-release window. The former remains inert migration input and
the latter remains non-executable reference data. Neither is a public command
contract.
