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

## Access application creation — Story Context

As a Maildesk operator provisioning a new dark environment, I need to create
one owned whole-host Access application before its operator policy exists, so
that provisioning can establish protection without inventing provider IDs or
opening access during setup.

## Happy Path

### AC-17: Create an initially protected application

**Given** a complete account inventory with no application sharing the requested name or hostname

**When** the operator approves and runs the exact application creation plan

**Then** cfctl reports verification only after the returned application identity has the requested whole-host settings and an empty policy set.

### AC-18: Continue using the verified identity

**Given** a verified newly created application

**When** the operator uses that application ID to prepare an operator-group Allow policy

**Then** cfctl produces a separate policy plan targeting the selected application.

## Edge Cases

### AC-19: Reject conflicting or unobservable ownership

**Given** an account inventory with a matching name, overlapping hostname or path, wildcard overlap, duplicate identity, or unclassifiable hostname ownership

**When** the operator requests application creation

**Then** cfctl rejects creation before a mutation is attempted.

### AC-20: Reject changed inventory

**Given** an approved creation plan whose account application inventory has changed

**When** the operator runs that plan

**Then** cfctl rejects the attempt and requires a new plan.

### AC-21: Use the current destination representation

**Given** a whole-host creation or update request

**When** its destination differs from the exact bare hostname

**Then** cfctl rejects the request.

## Error States

### AC-22: Preserve uncertain creation

**Given** a creation attempt without an identifiable successful provider response

**When** the operator inspects the operation

**Then** cfctl retains the original operation for recovery without automatically repeating creation.

### AC-23: Reject incomplete verification

**Given** a created application whose returned ID, policy set, login settings, destination or unique account ownership cannot be verified

**When** cfctl performs post-change verification

**Then** the operation is not reported as verified.

## Non-Functional Criteria

### AC-24: Preserve explicit security authority

**Given** application creation or compensation that changes Access protection

**When** the operator prepares the operation

**Then** cfctl requires approval of that exact security-affecting plan.

### AC-25: Keep compensation separate and visible

**Given** a successful application creation

**When** the operator reviews its compensation instructions

**Then** those instructions identify the exact returned application and warn that deleting it can expose a routed hostname.

## Notes — Access creation

- Creation uses the public catalog capability
  `access-applications-create-owned-self-hosted-whole-host`; policy creation uses
  `access-policies-create-operator-group-allow-policy` only after application
  identity verification. These are separate plans and approvals.
- Cloudflare's current [destination migration example](https://developers.cloudflare.com/fundamentals/api/reference/deprecations/)
  uses a bare hostname and makes `destinations` authoritative over the deprecated
  `self_hosted_domains` field. Creation does not send the deprecated field.
- [Access denies access by default](https://developers.cloudflare.com/cloudflare-one/access-controls/policies/).
  Empty policies establish the initial closed state; they do not establish
  operator login readiness. Routes remain dark until the application and
  intended policy are independently verified.
- Proof mapping: `cfctl-catalog::access_create::tests` covers schema derivation,
  provider drift, identity classification and separate create/update policy
  constraints; `cfctl-cloudflare::access_create::tests` covers absence, overlap,
  complete inventory and exact readback; runtime `access_create` binds and
  rechecks absence receipts. Existing consumed-plan and lifecycle tests cover
  replay exclusion. Local tests do not establish live deployment or login.

- The same fail-closed hostname classification and page-one inventory read also
  apply to owned whole-host updates. A terminal page without evidence of all
  preceding pages cannot establish ownership; unclassifiable applications
  cannot be silently excluded as unrelated.

## Site asset delivery — final bytes

**Story:** As a site visitor, I need immutable asset URLs to identify the exact
served content so that a new WASM build cannot reuse stale JavaScript glue.

### AC-26: Fingerprint the completed JavaScript

**Given** unchanged JavaScript and CSS inputs and changed WASM bytes

**When** the site creates its deployment assets

**Then** both WASM and JavaScript URLs change, CSS remains unchanged, and every
filename digest equals the final file bytes after rewriting the WASM import.

### AC-27: Reject asset delivery drift

**Given** an asset manifest and local or served content

**When** an asset's bytes differ from its declared digest, its path differs from
the exact declared filename, or JavaScript imports a different WASM asset

**Then** verification fails before it can report valid site asset delivery.

The fingerprint regression also rejects missing or ambiguous generated WASM
imports. Local proof and mocked fetch tests do not establish production
publication; live readback remains a separate post-deployment check.

## Noninteractive credential access

**Story:** As an operator or agent, I need ordinary cfctl commands to use their
established credential authority without asking for a Keychain password.

### AC-28: Never open a credential dialog

**Given** a terminal or unattended cfctl process accessing macOS Keychain

**When** it reads, writes, deletes or explicitly repairs a credential

**Then** it suppresses system interaction for the whole credential operation;
query or suppression failure prevents the credential API call.

### AC-29: Preserve process-wide interaction state safely

**Given** concurrent credential requests or an already disabled interaction flag

**When** cfctl enters and leaves the platform operation

**Then** one request cannot restore interaction during another request, and an
already disabled flag remains disabled. A failed access does not authorize
replacement or rotation of the existing evidence key.

Hermetic `quiet_keychain` tests exercise suppression failure, prior-disabled
state and concurrent restoration. Actual installed credential operability is
an independent readback; these tests never access the real Keychain.

## Adopted Maildesk evidence reads

### AC-30: Keep adopted reads closed and independently check policy state

**Given** a clean registered Maildesk workspace using its own namespace

**When** its declared `maildesk_v1` D1 evidence operation runs

**Then** cfctl runs only the compiler-owned query against its pinned configuration
and reports the revision R2 key and projection policy digest independently from
runtime policy state. Unsafe names, dirty selected workspaces, caller SQL,
missing fields and invalid private-shaped values fail closed. Old aggregates
never acquire new observations by inference, and route-health counts do not
establish inbox delivery.

### AC31 — Explicit private setup and restart

As an operator using a locally built CLI, I want routine Cloudflare operations
to work without password dialogs while retaining a clear local trust boundary.
Given an empty runtime or an existing platform runtime, when I prepare and
activate its exact private transition, then a fresh local authority is created,
ordinary account-pinned profiles and available selected credentials are carried,
and restart uses private storage even before the first token import. Doctor
reports deliberate private selection; no platform credential API is called.

### AC32 — Preserve history without reusing authority

Given old consumed, failed or uncertain operation history and approvals, when
a private transition activates, then the entire old state remains preserved,
the new runtime can list historical operation identities, and old IDs fail as
historical rather than missing or executable. No old approval, standing grant
or proof cache authorizes a new operation. Missing/excluded profiles and
unsupported standing references appear in the exact preview without values.

### AC33 — Atomic transition and safe concurrency

Given two normal invocations, when both hold runtime-selection guards, then
both may proceed under their existing resource locks. Given an active normal
invocation, when activation requests its exclusive guard, then activation fails
promptly before crossing; normal invocations likewise cannot cross activation.
Given source drift, a pending OAuth login, running execution or pending revoke,
when activation is requested, then it remains on the old runtime. Given an
interruption after staging, when the same transition resumes, then it retains
the staged generation and publishes the pointer only after initialization and
source revalidation pass.

### AC34 — Private file custody and source-only publication

Given private local storage, when a file or directory is linked, foreign-owned,
insufficiently private or oversized, then reads/writes fail without exposing
values. Given a source-only release, when the exact reviewed verified tag is
published, then it has no uploaded binary/installer assets and does not become
GitHub latest; prebuilt executable publication still requires the full signed
and notarized artifact contract.

### AC35 — Preserve restrictive policy during local setup

Given an active operator admission policy that blocks a capability, when I
prepare private setup, then the preview displays the same restrictive rules
and binds the exact source pointer and bundle. When I activate that reviewed
transition, then the new runtime retains those restrictions under a fresh
bundle and approval; an old approval is not copied. Malformed or drifted source
policy prevents activation, and interruption resumes the same staged bundle.
