---
artifact: acceptance-criteria
version: "1.0"
created: 2026-09-04
status: implementation-validation
---

# Acceptance Criteria: Truthful execution and recoverable observations

## Story Context

An operator must be able to prepare, approve, run and inspect an eligible
reversible operation when evidence attestation is unavailable, without losing
execution truth or manufacturing qualifying authority. Protected effects retain
their existing attestation and approval requirements. Application acceptance
semantics remain unchanged while the workspace-operation proposal is corrected.
This slice also keeps discovery of provider operations independent of an
unrelated dirty registered application. It does not implement the proposed
workspace pack format or establish release/deployment readiness.

## Happy Path

### AC-1: Eligible operation reaches an observed result

**Given** an eligible reversible operation with valid target and approval and unavailable evidence attestation

**When** the operator prepares, approves and executes the operation and its readback succeeds

**Then** its result reports the observed outcome and explicitly identifies its evidence as nonqualifying, without an attestation failure substituting for that outcome.

### AC-2: Healthy attestation remains qualified

**Given** available qualifying evidence authority

**When** an operation records its observations

**Then** those observations remain authenticated and available to the existing qualification checks.

### AC-3: Read-only recovery completes

**Given** an uncertain eligible operation and unavailable evidence authority

**When** a read-only recovery establishes the exact intended state

**Then** the operation closes with the observed verification result and nonqualifying evidence, without replaying its mutation.

## Edge Cases

### AC-4: Provider discovery ignores unrelated application dirt

**Given** an unrelated dirty registered application

**When** the operator resolves a natural-language provider request or an exact provider capability ID

**Then** provider discovery returns its normal resolution result without validating the unrelated application's operation pack.

### AC-5: Selected workspace operation still requires clean authority

**Given** a dirty registered application that owns the selected workspace operation

**When** the operator resolves that exact operation

**Then** resolution fails closed with the workspace validation error.

### AC-6: Irreversible or unknown effects remain protected

**Given** unavailable evidence authority and an irreversible or unknown effect or risk classification

**When** execution is requested

**Then** it refuses before a provider mutation and retains the original authority refusal.

## Error States

### AC-7: Receipt survives local evidence failure

**Given** a delegated operation has returned a receipt showing a crossed boundary

**When** apply evidence cannot be persisted

**Then** the response retains the redacted receipt, reports that execution occurred, and directs recovery without replay.

### AC-8: Recovery persistence can also fail

**Given** a returned delegated receipt and failed apply-evidence persistence

**When** recovery-state persistence also fails

**Then** the response still reports the known boundary outcome, names both failures, and instructs recovery without replay.

### AC-9: Local rejection reports no attempt

**Given** a delegated operation that fails locally before starting

**When** the operator inspects its result

**Then** the result reports not attempted with the consumed plan preserved.

### AC-13: Timeout preserves uncertainty

**Given** a delegated operation that times out after starting

**When** the operator inspects its result

**Then** the result reports an uncertain attempted outcome with the consumed plan preserved.

## Non-Functional Criteria

### AC-10: Audit evidence cannot grant authority

**Given** an explicitly unattested observation

**When** a caller attempts to use it as authenticated evidence or a qualifying proof

**Then** qualification refuses, and strict authority writes remain strict.

### AC-11: Observation secrets are redacted

**Given** secret-bearing observation fields

**When** observations are recorded or returned after persistence failure

**Then** the secret values are redacted.

### AC-14: Observation scope remains isolated

**Given** independently scoped operations sharing one state root

**When** one operation selects nonqualifying observations

**Then** the other operation's observation mode remains unchanged.

### AC-12: Application semantics survive proposal correction

**Given** the current inbound acceptance and route-health contracts

**When** the proposed generic workspace format is evaluated for replacement

**Then** column shape alone is explicitly insufficient, all current identity/completeness predicates retain owners, and removal is blocked until semantic equivalence and consumer cutover are proved.

### AC-15: Canonical publication proof

**Given** a clean canonical checkout and one branch or new annotated tag identifying its exact HEAD

**When** the publication gate runs

**Then** it verifies that checkout with inherited Git context removed and admits publication only while the ref, HEAD, and source remain unchanged.

### AC-16: Publication refuses unsafe proof inputs

**Given** dirty source, a non-HEAD ref/object, a lightweight or existing tag, a bypass request, or failed local proof

**When** the publication gate runs

**Then** it refuses publication without creating a linked checkout or weakening global Git protections.

## Verification trace

These are source/local-proof criteria. They do not substitute for independent
candidate review, signed release verification, installation, or live readback.

| Criteria | Direct verification |
|---|---|
| AC-1 | `unattested_observations_complete_apply_verify_and_recovery_without_qualifying`; actual observation writers at prepare/approve/live-precondition/apply/verification call sites reviewed together |
| AC-2, AC-14 | `observation_scope_does_not_change_authenticated_writes_or_original_store` |
| AC-3 | `unattested_get_only_recovery_closes_without_authority_promotion` |
| AC-4, AC-5 | `dirty_registered_pack_does_not_block_cli_resolve_for_an_unrelated_intent` |
| AC-6 | Existing `compensation_and_errors` attestation effect/risk matrix, including unavailable authority and unknown classification |
| AC-7, AC-8, AC-11 | `returned_delegated_receipt_survives_evidence_and_recovery_storage_failure` |
| AC-9 | Existing `delegated_local_failure_after_consumption_does_not_claim_a_provider_attempt` |
| AC-13 | Existing `delegated_timeout_persists_unknown_outcome_and_returns_no_replay_guidance` |
| AC-10 | `identical_unattested_body_cannot_refresh_existing_qualified_evidence`, new observation tests, and unchanged strict evidence/proof qualification tests |
| AC-12 | `workspace-operation-format.md` ownership/predicate mapping; existing workspace D1 evidence projection tests remain unchanged |
| AC-15, AC-16 | `pre_push_gate_binds_canonical_source_and_cleans_git_environment` exercises real temporary Git repositories with a bounded fake proof command; complete source proof still runs through `cargo xtask verify` at actual publication |

## Notes

- Provider transport is not exercised by the new deterministic persistence tests;
  those begin with a returned boundary receipt or exact readback. No live effect
  is needed to prove failure accounting and evidence classification.
- The strict evidence writer and authenticated proof readers are unchanged.
  Scoped observation writes create redacted body-only audit evidence and mark
  it nonqualifying; they never silently retry an authenticated write as audit.
- Full `cargo xtask verify` applies to the final combined candidate. Source
  inspection and focused tests alone do not establish release or live readiness.
- A new specialized Access application creation contract is a separate addition
  to be specified and validated before the overall deployment acceptance claim.
