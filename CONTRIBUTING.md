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
their local path. New licenses, registries, Git sources, duplicate versions, or
secret-scan exceptions require explicit review; do not broaden `deny.toml` or
`.gitleaksignore` merely to pass the gate.

## Extending the runtime

- Public contracts and redaction: `crates/cfctl-core`
- Credentials and profiles: `crates/cfctl-auth`
- API/schema/docs/CLI ingestion: `crates/cfctl-catalog`
- Cloudflare HTTP execution: `crates/cfctl-cloudflare`
- Risk, cost, approval, and impact: `crates/cfctl-planner`
- Registered-root and IaC discovery: `crates/cfctl-workspace`
- Agent installation and handoff: `crates/cfctl-agent`
- Plans, locks, imports, and evidence: `crates/cfctl-storage`
- Public parsing and orchestration: `crates/cfctl-cli`
- Verification and release assembly: `xtask`

See [SECURITY.md](SECURITY.md) for private vulnerability reporting and
[docs/v2-security.md](docs/v2-security.md) for the runtime security contract.
