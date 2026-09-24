# Docs

Doctrine lives at the repository root: [`NORTH_STAR.md`](../NORTH_STAR.md),
[`ANCHOR.md`](../ANCHOR.md), [`LAYERS.md`](../LAYERS.md). This directory holds
contracts, procedures, and migration evidence. It does not grant authority.

## Operator

| Document | Owns |
|---|---|
| [runbooks/cfctl.md](runbooks/cfctl.md) | triage, health, recovery |
| [runbooks/capability-procedures.md](runbooks/capability-procedures.md) | per-capability reads and writes |
| [runbooks/tool-choice.md](runbooks/tool-choice.md) | adapter status order |
| [agent-landing.md](agent-landing.md) | first-load agent doctrine |
| [../QUICKSTART.md](../QUICKSTART.md) | install, authenticate, first write |

## Contract

| Document | Owns |
|---|---|
| [runtime-policy.md](runtime-policy.md) | what needs approval |
| [v2-security.md](v2-security.md) | secrets, hashing, redaction, evidence |
| [capability-safety-contracts.md](capability-safety-contracts.md) | per-capability safety dependencies |
| [v2-architecture.md](v2-architecture.md) | crates, trust sequence |
| [command-language.md](command-language.md) | public grammar |

## Surfaces

| Document | Owns |
|---|---|
| [pages-direct-setup.md](pages-direct-setup.md) | empty Pages projects and first-upload proof |
| [r2-private-capture.md](r2-private-capture.md) / [r2-private-restore.md](r2-private-restore.md) | private R2 capture and restore |
| [worker-frozen-artifact-upload.md](worker-frozen-artifact-upload.md) / [worker-version-artifact-digest.md](worker-version-artifact-digest.md) | frozen Worker artifacts |
| [workspace-d1-reads.md](workspace-d1-reads.md) / [workspace-d1-transitions-v3.md](workspace-d1-transitions-v3.md) | reviewed D1 inventories |
| [workspace-operation-format.md](workspace-operation-format.md) | in-progress pack contract (generic loader; typed evidence validators still win) |
| [telemetry-control-plane.md](telemetry-control-plane.md) | bounded telemetry and security-response |
| [response-header-rule-repair.md](response-header-rule-repair.md) | targeted header-rule repair |
| [custom-challenge-rule-repair.md](custom-challenge-rule-repair.md) | existing custom challenge expression repair |

## Migration and reference

| Document | Owns |
|---|---|
| [compat.md](compat.md) / [v1-parity.md](v1-parity.md) | v1 quarantine boundary |
| [official-cloudflare-reference.md](official-cloudflare-reference.md) | upstream doc links |
| [upstream-schema-gaps.md](upstream-schema-gaps.md) | blocked-capability root causes |
| [architecture/adr/](architecture/adr/) | accepted architecture decisions |
