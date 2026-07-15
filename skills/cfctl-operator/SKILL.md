---
name: cfctl-operator
description: Operate, extend, or diagnose Cloudflare through this repository's governed cfctl runtime. Use for Cloudflare account reads, API discovery, Workers and Wrangler work, tunnels, dashboard-only tasks, desired state, deployment, incident response, or any task that may need Browser Run or Computer Use as a fallback. Produces a scored SKILL_CHOICE before selecting an execution adapter and records evidence-backed outcome metrics afterward.
---

# cfctl Operator

Use `cfctl` as the authority-preserving command bus. Select the best execution adapter from current requirements, execute only within its existing authority, verify the result, and record the outcome.

## Workflow

1. Read the repository `AGENTS.md` and use the local `./cfctl` when `cfctl` on `PATH` is unavailable.
2. Run `cfctl doctor` when the task depends on live account trust, authentication, previews, locks, or artifact health.
3. Express the task as a non-secret, bounded intent. Never put credentials, private payloads, or personal data in `--intent` or command arguments.
4. Classify risk as `read`, `write`, `destructive`, `secret_sensitive`, `external_communication`, or `spend`.
5. Add concrete capabilities with repeatable `--need` flags. Inspect available names with `cfctl skills list`.
6. Declare an adapter with `--available <adapter>` only when its tool is actually callable in the active session.
7. Run `cfctl skills choose` and inspect the emitted `SKILL_CHOICE` receipt:

```bash
cfctl skills choose \
  --intent "Inspect a live Worker configuration and verify it" \
  --risk read \
  --need live_read \
  --need verification
```

8. Stop if `decision.status` is `blocked`. Satisfy the stated availability requirement or extend the runtime; do not silently choose an ungoverned path.
9. Execute through the selected adapter using the rules below.
10. Record `verified`, `failed`, `fallback`, or `abandoned` against the choice. A `verified` outcome requires an existing evidence path:

```bash
cfctl skills record \
  --choice-id <choice-id> \
  --adapter <adapter-id> \
  --outcome verified \
  --duration-ms <milliseconds> \
  --evidence <artifact-path> \
  --evidence-class post_change_verification
```

11. Use `cfctl skills metrics` to inspect observed outcomes. Treat null rates as no evidence, not zero performance.

## Adapter Rules

### cfctl-native

Use for catalogued control-plane reads and writes, standards, desired state, token lifecycle, incidents, and verification. Read current state first. For writes, run `classify`, `guide`, and `apply ... --plan`; review the receipt; apply only with the matching `--ack-plan`; then run `verify`.

### cloudflare-api-mcp

Use official Cloudflare API MCP discovery for uncatalogued endpoints and current schemas. It expands endpoint coverage but does not expand authority. Read-only discovery and live reads may execute directly when allowed. Do not perform a mutation until cfctl has an operation-specific preview, acknowledgement, redaction, and verification contract; extend the public runtime when that contract is absent.

### cfctl-wrangler

Use `cfctl wrangler ...` for Worker and developer-platform operations. Read-only subcommands run in the wrapper envelope. Mutating subcommands require its plan and acknowledgement flow.

### cfctl-cloudflared

Use `cfctl cloudflared ...` for tunnel runtime, connectivity, and local ingress. Do not treat cloudflared output as complete account inventory.

### browser-run

Prefer a purpose-built browser tool for rendered pages, browser sessions, or web UI state. Keep the scope bounded. Cloudflare mutations remain subject to cfctl preview and verification; external communications and spend require the applicable confirmation policy.

### Computer Use

Use Computer Use only when a purpose-built API, connector, CLI, or browser tool is unavailable or insufficient and the active signed-in UI can unblock the task. Confirm the selected window or page and capture before/after state. Computer Use never bypasses cfctl mutation previews, destructive confirmation, external side-effect confirmation, secret handling, or post-change verification. If the UI is the only mutation surface and no cfctl preview contract exists, stop and extend cfctl before changing state.

## Trust Invariants

- A `SKILL_CHOICE` recommends an adapter; it grants no authority.
- Declared policy metrics rank candidates. They are not success evidence.
- Observed metrics come only from one persisted `SKILL_OUTCOME` per choice. Verified outcomes require separate, content-hashed evidence; the choice receipt cannot prove itself.
- Raw intent is not persisted; the receipt stores its SHA-256 digest and length.
- Agent memory, prose, and screenshots alone do not prove live Cloudflare state.
- Source-config proof, live read proof, preview proof, apply proof, and post-change verification remain distinct.
- Never mark a task verified without an evidence path that supports the claim.
