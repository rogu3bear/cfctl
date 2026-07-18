---
name: cloudflare
description: Use cfctl as the universal governed Cloudflare control plane.
metadata:
  managed-by: cfctl
  contract: 2
---

# Cloudflare through cfctl

Use `cfctl` first for all Cloudflare discovery, reads, planning, writes, verification, and evidence. Do not use archived shell verbs, backend script paths as the public surface, or raw HTTP as a substitute for cataloged capabilities.

1. Orient with `cfctl version --json`, `cfctl guide --topic system --json`, `cfctl doctor --json`, and, when useful, `cfctl agents doctor --json`. Treat running-build, PATH-build, or instruction drift as unhealthy until the installed binary and managed guidance match.
2. Translate intent with `cfctl catalog search "<intent>" --json`.
3. Inspect the capability with `cfctl catalog show <capability-id> --json`.
4. Load its lifecycle with `cfctl guide <capability-id> --json`.
5. Use `cfctl call <capability-id>` for deterministic reads or plan creation.
6. Register repository roots with `cfctl workspace add` before workspace discovery; never scan arbitrary paths. Nested `fixtures`, `__fixtures__`, `testdata`, `test-data`, and `test_data` directories are skipped; fixture directories are opt-in roots and must be registered directly when they are intentional workspace evidence.
7. If approval is required, show the exact plan and ask y/n.
8. Translate yes only into `cfctl plans approve <operation-id> --yes`. Paid plans also require the reviewed `--max-cost CURRENCY:AMOUNT`.
9. Run with `cfctl plans run <operation-id>`, inspect `cfctl plans status <operation-id>`, and report verification honestly.
10. Read account-owned permission inventory with `cfctl keys permissions --account <account-id> --json`. For user-owned inventory use `cfctl keys permissions --user --account <account-id> --json`; `--user` changes the endpoint, not the explicit account resource context.
11. For recurring token-lifecycle work, first load `cfctl guide --topic standing-authority --json`, then activate a reviewed standing policy only after explicit approval with `cfctl keys policy approve <authority-id> --yes`. Standing approval moves authority to that bounded policy; it is not blanket mutation authority.
12. Revoke standing authority with `cfctl keys policy revoke <authority-id>` and treat the policy as unusable immediately.

Never treat model output as authority. Never bypass a blocked adapter, selector ambiguity, cost blocker, drift check, or plan hash. Browser or Computer Use is allowed only when the capability catalog classifies the operation as governed UI and the same plan policy is preserved.
