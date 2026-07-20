# Contributing to cfctl

`cfctl` is a strict, catalog-driven Cloudflare control plane. A change is ready
only when its public contract, deterministic behavior, safety metadata, tests,
documentation, and evidence model agree.

## Ground rules

- `cfctl` is the only public interface. Do not reintroduce the archived v1
  shell runtime, expose flat backend scripts, hand-roll Cloudflare auth, or add
  a Cloudflare API MCP dependency.
- Search the catalog before adding behavior. New writes remain blocked until
  risk, effect, cost, permission, entitlement, verification, and rollback or
  explicit irreversibility are known.
- Reads are not plans, plans are not applies, and apply artifacts are not
  post-change verification. Keep those evidence classes distinct.
- All mutations use the one-use `PlanV1` lifecycle. Never weaken approval,
  account/target binding, catalog hashes, drift checks, locks, journals,
  verification, or rectification to make a capability executable.
- Secret inputs come from stdin or the platform secret store. Secret outputs
  require `--value-out`; values never belong in arguments, stdout, plans,
  logs, fixtures, or repository files.
- Workspace discovery stays inside explicitly registered roots. Preserve
  unrelated dirty work and report exact local diffs.

## Development setup

Rust 1.93 is pinned by the repository. Install `cargo-deny` and Gitleaks for
the local proof lane, then orient through the public CLI:

```bash
./bootstrap.sh
cfctl version --json
cfctl doctor
cfctl catalog sync
cfctl catalog coverage
cfctl workspace discover
cfctl workspace audit
cargo xtask verify
```

Bootstrap requires a tracked-clean checkout, proves the installed binary is
the exact `HEAD` commit, synchronizes only managed agent integrations, and runs
both doctors. Use `--check-only` for source proof or `--skip-agent-sync` for an
intentional binary-only install.

Authentication is optional for offline development. Use `cfctl auth login` or
an explicitly scoped token profile when live-read proof is required; never
create a repository `.env` with Cloudflare credentials.

### Pre-push gate

Remote CI is intentionally absent, so nothing catches a gate that was never
run — this repository has shipped a red `main` that way. `.githooks/pre-push`
runs `cargo xtask verify` and refuses the push when it fails.

The hook is tracked, but it does not run merely because you cloned the
repository. It executes only where an agentOS-style delegate pins its digest in
`~/.agent/repo-hook-allowlist`, and an unregistered repository is passed over
silently. Register it per machine:

```bash
shasum -a 256 .githooks/pre-push
# append to ~/.agent/repo-hook-allowlist:
#   <absolute-repo-root> pre-push=<digest>
```

`cargo xtask verify` reports when this checkout's hook is unregistered or
pinned to a stale digest, and prints the exact line to add. Editing the hook
without re-pinning blocks every push until the allowlist is updated; that
tripwire is deliberate.

Gate logic lives in `.githooks/pre-push-gate.sh`, which is not pinned, so it can
change without re-pinning. `CFCTL_PRE_PUSH_GATE=off` skips the gate for genuine
emergencies — prefer it over `git push --no-verify`, which also skips the global
branch and tag deletion policy.

Without the delegate, treat `cargo xtask verify` before every push as a manual
obligation.

## Making a change

1. Identify the owning crate and the catalog capability or public contract.
2. Add a failing test or contract fixture that demonstrates the missing
   behavior.
3. Implement the smallest complete change, including catalog metadata and
   documentation when the public surface changes.
4. Run `cargo xtask verify`.
5. For live behavior, use a selected non-production account and report the
   evidence class for every claim. Account-backed disposable mutations remain
   a separate, explicitly acknowledged smoke lane.
6. Describe blockers honestly. Unknown cost, entitlement, permissions,
   verification, or rollback is contract debt—not authority to execute.

Internal path dependencies must include the exact workspace version as well as
their local path; `verify` checks that by equality, because Cargo alone accepts
a stale pin. A version bump must therefore update every intra-workspace pin and
`QUICKSTART.md`'s download path in the same change. New licenses, registries,
Git sources, duplicate versions, or secret-scan exceptions require explicit
review; do not broaden `deny.toml` or `.gitleaksignore` merely to pass the gate.

Every `cfctl` example is linted against the single-sourced command tree in
`crates/cfctl-core`, at full subcommand depth, in all tracked files and in the
managed agent instructions. A stale or mistyped example fails `verify`
regardless of which file it lives in.

## Extending the runtime

Crate boundaries decide where a change belongs. `docs/v2-architecture.md`
carries the table with each crate's boundary; this file does not restate it,
because a second copy is a second thing to keep true.

## Release lanes

Three separate lanes, deliberately split so identity-bearing steps are never a
side effect of building:

- `cargo xtask assemble` builds Apple arm64/x86_64 and Linux musl arm64/x86_64
  **twice** and compares hashes, creates SPDX SBOMs and provenance, and renders
  the Homebrew formula and the checksum-verifying Linux installer. It stops
  before any Apple or Sigstore activity.
- `cargo xtask release` repeats that proof, then signs and notarizes both macOS
  binaries against explicit operator-supplied identities and signs checksums
  and provenance.
- `cargo xtask publish` rechecks every identity and uploads the complete
  four-platform set, one asset at a time, to an empty draft release.

Making a draft public is always a separate operator action.

The signing lane is available tooling, not the current posture: **published
releases are unsigned by operator decision**, with integrity from `SHA256SUMS`,
reproducible double-builds, SPDX SBOMs, and commit-bound provenance. Because
the rendered Linux installer verifies a Cosign identity and has no
checksum-only fallback, it is deliberately not shipped with unsigned releases.
GitHub-hosted Rust builds are intentionally absent.

An account-backed disposable token smoke test
(`tests/account-backed-smoke.sh`) is kept out of the local proof lane because
it mutates a real account. It requires an explicit disposable account,
profile, reviewed permission group, and acknowledgement gate before it mints,
rotates, revokes, and verifies one short-lived token.

See [SECURITY.md](SECURITY.md) for private vulnerability reporting and
[docs/v2-security.md](docs/v2-security.md) for the runtime security contract.
