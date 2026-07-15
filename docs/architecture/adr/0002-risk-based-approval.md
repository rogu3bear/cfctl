# ADR 0002: Hash-bound, risk-based approval

- Status: accepted
- Date: 2026-07-14

## Context

A universal Cloudflare tool includes ordinary reads, reversible edits, credential retrieval, external communication, deletes, account ownership, billing, registrar actions, and operations whose cost or rollback semantics are absent from the official schema. A blanket “yes for every write” is noisy, while a model deciding authority is unsafe.

## Decision

The deterministic policy engine—not an agent—decides whether a capability is automatically executable, approval-required, or blocked. Automatic execution is limited to known, single-target, scoped, reversible operations with no dependent configuration, identity effect, external communication, incremental cost, or unknown semantics.

Approval is the mutation `cfctl plans approve <operation-id> --yes`. It binds to the plan content hash and expires no later than 24 hours after creation. Catalog drift, request drift, target drift, or a changed precondition invalidates the approval. Paid plans require an explicit `--max-cost CURRENCY:AMOUNT`; unknown cost remains blocked.

The plan is durably marked consumed before crossing the Cloudflare, subprocess, or UI boundary. A crash after that point cannot replay the operation automatically. Destructive, identity, external-send, registrar, billing, irreversible, cross-repository, and unknown-risk changes require approval. UI handoff creates `AgentActionV1`; it never proves execution by itself.

## Consequences

- Agents may translate a user’s “y” only into approval of the exact operation ID shown to that user.
- Successful execution without a capability-specific verifier remains `rectification_required`, not “done.”
- Secret values use sink-only delivery and never enter stdout, plans, logs, or evidence.
- Unsupported verification and non-reversible effects are reported explicitly.
