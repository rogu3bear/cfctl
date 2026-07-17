---
name: cfctl-operator
description: Operate, extend, or diagnose Cloudflare through the governed Rust cfctl runtime. Use for capability discovery, live account reads, mutation planning, token lifecycle, workspace and IaC impact, Wrangler or cloudflared delegation, and governed UI handoffs.
---

# cfctl operator

Use `cfctl` as the only public Cloudflare control plane. The catalog selects an
implemented adapter; model output never grants authority or directly mutates
Cloudflare.

## Workflow

1. Read the repository `AGENTS.md`. Use local `./cfctl` if `cfctl` is absent
   from `PATH`.
2. Orient and refresh current official capability data:

   ```bash
   cfctl version --json
   cfctl doctor
   cfctl catalog sync
   cfctl catalog coverage
   cfctl agents doctor
   ```

3. Discover and inspect the capability before acting:

   ```bash
   cfctl catalog search "<bounded non-secret intent>"
   cfctl catalog show <capability-id>
   cfctl guide <capability-id>
   ```

4. Use `cfctl call` for live reads. Cite the resulting live Cloudflare read;
   repository configuration is only source evidence.
5. Register repository boundaries explicitly before workspace analysis. Use
   `workspace discover`, `graph`, and `audit`; never scan arbitrary roots.
   Nested `fixtures`, `__fixtures__`, `testdata`, `test-data`, and `test_data`
   directories are skipped. Register a fixture directory directly to opt it in.
6. A mutating call creates a plan rather than changing Cloudflare. Review its
   operation ID, selected account, exact targets, Cloudflare and local diffs,
   permission lane, entitlement, cost, verification, compensation, and
   warnings.
7. If approval is required, translate explicit operator consent only into:

   ```bash
   cfctl plans approve <operation-id> --yes
   ```

   Paid plans also require the reviewed `--max-cost CURRENCY:AMOUNT`. Unknown
   or unbounded cost stays blocked.
8. Execute only with `cfctl plans run <operation-id>`, then inspect `plans
   status`. Use `plans rectify` after uncertain boundary crossing or unsupported
   verification; never replay a consumed plan.
9. Read account-owned permission inventory with `cfctl keys permissions
   --account <account-id> --json`. For user-owned inventory use `--user` while
   retaining the same explicit account context.
10. For recurring token lifecycle, load `cfctl guide --topic
   standing-authority --json`, approve only the exact reviewed policy with
   `cfctl keys policy approve <authority-id> --yes`, and revoke it with `cfctl
   keys policy revoke <authority-id>`.
11. Report source config, live read, preview, apply, post-change verification,
   local proof, and agent action as distinct evidence classes.

## Adapter rules

- `native`: operation-specific cfctl behavior, including inventory-bound token
  mint, rotation, revocation, and sink-only credential handling.
- `dynamic_api`: schema-validated Cloudflare HTTP execution selected from the
  pinned catalog.
- `delegated_cli`: governed Wrangler or cloudflared subprocess with a cleared
  environment, one selected credential, timeout, redaction, and receipt.
- `governed_ui`: target-bound `AgentActionV1` only after API and CLI
  insufficiency is established. It is a handoff, not approval or completion.
- `blocked`: discovery only. Satisfy the named contract gap or extend cfctl;
  never route around it.

## Trust invariants

- Profiles and workspaces pin one account; ambiguity fails closed.
- Running-build, PATH-build, and managed-instruction drift is unhealthy; repair
  installation before relying on the operator surface.
- Secrets enter through stdin or the platform secret store. Secret-producing
  calls require a new `--value-out` destination.
- Mutation contracts must know risk, effect, cost, permissions, entitlement,
  verification, and rollback or irreversibility.
- Deletes, purges, identity/security/ownership changes, external sends,
  registrar/billing actions, irreversible data changes, cross-repository
  changes, unknown-risk work, and paid actions always require explicit
  approval.
- A plan, handoff, screenshot, or evidence file is not post-change
  verification merely because it exists.
