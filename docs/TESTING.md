# Testing

## Test Strategy

This safety-net pass began on 2026-10-19 against
`aaedc6f1b4d11c8ea41fb0ac440bec8ecfcb1b79`, on the canonical checkout's `main`
branch. It characterizes `cfctl-planner::PolicyEngine::evaluate` through the
existing public API. Phase 1 left planner production code, dependencies, and
runtime contracts unchanged. The tests reuse the existing complete reversible-write fixture;
cases intended to reach effect or risk policy assert that contract admission
succeeds first, so an unrelated metadata rejection cannot masquerade as coverage.

The planner is a bounded first target because it decides the compiled approval
floor used by plan preparation and later policy checks. The highest recent
source churn is in workspace operation discovery and ownership; that boundary
already has targeted declaration/ownership regression tests. The planner has
lower churn but broad authority impact and missing decision-combination coverage.

Effect sketch: capability metadata and workspace impact enter `evaluate`;
selector, dirty-overlap, adapter, and mutation-contract guards can return early;
remaining inputs produce an automatic or approval-required decision. The result
contains schema version, disposition, ordered reasons, and a cost-ceiling flag.
CLI consumers in `runtime/plan_prepare.rs` and `runtime/plan_commands.rs` use
the compiled decision in policy evaluation and policy hashes. The public
function is already pure, so this pass needs no dependency seam or test double.

Focused command:

```sh
cargo test --locked --offline -p cfctl-planner -j 2
```

Baseline: 1 unit test and 7 integration tests passed. After adding 10
characterization tests: 1 unit test and 17 integration tests passed. These
results exercise local policy decisions, not provider execution, installation,
or acceptance of a plan. No planner behavior defect has been established.

Initial verification on the expanded candidate:

- Focused planner tests: 18 passed, 0 failed.
- `cargo clippy --locked --offline -p cfctl-planner --all-targets -j 2 -- -D warnings`:
  passed.
- `cargo fmt --all -- --check` and `git diff --check`: passed.
- The documented two-stage enclosing proof built `xtask`, passed attribution,
  root formatting, and warnings-denied workspace Clippy, then failed during
  `cargo test --workspace --all-targets --locked`: 1,999 passed, 1 failed,
  7 ignored across 36 completed targets. The failure is
  `local_guidance::tests::repository_exact_ignored_paths_are_covered` in `xtask`.
  The pre-existing `.gitignore` addition names `/CLOUDFLARE.md`, while
  `xtask/src/local_guidance.rs` does not inventory that note. This pass changed
  neither input; all four pre-existing dirty-file hashes remain identical.
- The verifier stopped at that test failure. Its later request-contract, site,
  bridge, security/source-governance, and Linux cross-build stages did not run
  as enclosing stages of this attempt. Some native tests cover their contracts;
  that does not establish completion of those later stages.

The full run is retained at
`/Users/star/Documents/Codex/2026-10-19/new-chat/outputs/cfctl-safety-net-proof.log`.
That attempt left Phase 1 `awaiting-evidence`.

The user then authorized the narrow inventory repair and an enclosing rerun.
`CLOUDFLARE.md` is now in `LOCAL_AGENT_FACING_NOTES`, so the existing domain and
archived-command checks reach it by name. The existing known-path test now
includes its root-anchored spelling. All 5 focused local-guidance tests passed,
including rejection of unknown exact paths and significant leading whitespace.
The directive, ignore rule, planner tests, and prior runbook changes retain their
starting hashes.

The first follow-up enclosing run then failed in the parallel CLI integration
suite: `auth_import::exclusive_lock_observation_rejects_shared_and_unlocked_states`
could not acquire its fixture's exclusive lock after dropping shared guards.
The unchanged fixture passed alone. A controlled local reproduction confirmed
that a fork can retain a shared descriptor after the parent's close; the actual
descriptor owner from the failed suite was not captured. The fixture now runs
its existing assertions in a dedicated child test process, using the existing
10-second child timeout and cleanup. The parent also checks that exactly one
test passed, so a renamed or missing test cannot silently run zero assertions.
All 47 CLI integration tests passed after this isolation, followed by 3 more
default-parallel CLI runs with 47 passed and 0 failed each. Production locking
is unchanged.

The final enclosing rerun passed with exit 0 on 2026-10-19 (America/Chicago),
using `cargo build --locked -p xtask` followed by `./target/debug/xtask verify`:

- Attribution, root formatting, and warnings-denied workspace Clippy passed.
- All 36 workspace test targets passed: 2,000 passed, 0 failed, 7 opt-in ignored.
  The repaired inventory check and the CLI lock fixture both passed in that run.
- The separate provider request-contract run passed all 203 tests.
- Site formatting, Clippy, 7 Rust tests, and 18 Bun tests passed. The two edge
  builds reproduced digest
  `0bebb63577ce520c6b8d1a4af14446238fc748e5a8f348dfcb72c526aebb134b`.
- Bridge frozen installation, generated-type checks, TypeScript, and 3 Bun tests
  passed. Dependency advisories, bans, licenses, and sources passed; full-history
  scanning reported no leaks across 856 commits.
- Source/governance checks and the Linux x86_64 musl cross-build passed.

All 17 recorded input hashes, HEAD, and source status matched after the run,
including the directive, earlier dirty work, and unchanged planner tests.
The full successful log is
`/Users/star/Documents/Codex/2026-10-19/new-chat/outputs/cfctl-safety-net-proof-after-lock-fixture-fix.log`.
The intervening failed rerun remains in `cfctl-safety-net-proof-after-guidance-fix.log`.
Phase 1 closed as `done` for this bounded Safety Net Map. The remaining
characterization gaps below stay in the backlog. No later phase had started at
that closure; the user subsequently selected Phase 2 as recorded below.
The Phase 1 closing records were finalized after that successful proof, with
its verified Rust source and guidance bytes unchanged at closure.

## Phase 2 Verification

The user selected consistency/readability work on the pinned planner code.
Baseline and changed planner suites both passed 18 tests. No existing test
assertion, condition, policy reason, ordering rule, public signature, or metadata
gap was changed. The implementation now uses one private constant for the
incremental-cost reason, imports `AdapterStatus` consistently, and initializes
the approval accumulators after the unchanged blocking guards. Two comments
explain the guard precedence and policy-hash ordering contract.

The larger helper-interface cleanup remains deferred in the Debt Ledger.
The Phase 2 enclosing proof passed with exit 0 on the changed source using the
documented two-stage route:

- Attribution, root formatting, and warnings-denied workspace Clippy passed.
- All 36 workspace test targets passed: 2,000 passed, 0 failed, 7 existing
  optional tests ignored. The separate request-contract run passed 203 tests.
- Site formatting and Clippy, 7 Rust tests, 18 Bun tests, and both reproducible
  edge builds passed. The reproduced digest remained
  `0bebb63577ce520c6b8d1a4af14446238fc748e5a8f348dfcb72c526aebb134b`.
- Bridge frozen installation/type checks/TypeScript and 3 Bun tests passed.
  Dependency advisories, bans, licenses, sources, and the full-history secret
  scan passed. Source/governance checks and the Linux musl cross-build passed.

All 18 frozen input hashes, HEAD, and source status matched after the run.
The full log is
`/Users/star/Documents/Codex/2026-10-19/new-chat/outputs/cfctl-phase-2-enclosing-proof.log`.
Phase 2 is `done` for the pinned planner scope. Its closing documents were
finalized after proof; verified code, prior dirty work, and directive bytes
remain unchanged. No Phase 3 work had started at that closure.

## Phase 3 Verification

On 2026-10-20, the user selected the planner helper interfaces for Phase 3 and
required the missing combinations to be pinned before refactoring. Six tests
are appended to `crates/cfctl-planner/tests/policy.rs`; all 17 earlier integration
tests remain byte-for-byte unchanged:

- `read_metadata_keeps_cost_risk_and_impact_decisions`: seven explicit decisions
  cover known/unknown cost, incremental/non-incremental cost, Read/ScopedWrite/
  CrossConfig/Unknown risk, the read shortcut, and combined impact reasons.
- `charged_reads_keep_early_block_precedence_and_clear_ceiling`: six combinations
  cover known/unknown charged reads against selector, dirty, and adapter blocks.
- `non_mutating_spend_keeps_cost_guard_and_reason_order`: four cost combinations
  distinguish hard-ceiling rejection from approval, cost-reason deduplication,
  and cost insertion before or after impact reasons.
- `missing_rollback_declaration_blocks_before_known_cost_approval`: six cases
  cover absent automatic strategy, absent/manual-default warning, and known
  incremental cost before approval accumulation.
- `declared_manual_rollback_keeps_reversible_write_approval_and_order`: six cases
  cover ScopedWrite/Read/CrossConfig risk without automatic rollback, with and
  without incremental cost and combined impact reasons.
- `non_mutating_unknown_effect_keeps_effect_and_risk_reasons`: two cases pin
  the reachable Unknown effect/risk branch with and without incremental cost.

These were initially 31 authored cases awaiting execution. The synthetic
non-mutating metadata exercises a pure policy boundary and does not establish runtime
capability validity. Mutation fixtures use the existing contract fixture;
declared manual rollback is admitted by the current core predicates.

`cargo fmt --all -- --check` and `git diff --check` passed after the additions.
At characterization, the planner implementation still matched the Phase 2 verified fingerprint
`62766f42a67a6cbeec4b3c112b4c3ec2cd17394193425494f5c35f6110154109`.
At the initial hold, no new assertion had compiled or run. The admission query
`disk-guard explain -- cargo test --locked --offline -p cfctl-planner -j 2`
returned `LANE_BUSY` (exit 75), naming reservation
`0079c90b68844b6cbdabf1390de61611` in `/Users/star/dev/mln-research-site`, operation
`research-site-preview`, with unknown output-lane coverage. Its owner process
14845 was observed running. The reservation and preview remain untouched.

On the user's requested recheck, fresh admission returned `ADMISSIBLE` with
`CAPACITY_AVAILABLE`. This task made no change to the preview or its reservation.
The expanded planner suite then passed 24 tests (one unit and 23 integration),
including all six new tests and 31 cases, on unchanged Phase 2 production source.
The characterization log and source fingerprints are captured in the task's
`outputs/cfctl-phase-3-characterization-receipt.json`. The new assertions now
extend the Safety Net Map below. This established the required green baseline
before either helper transformation.

Both helper transformations then passed the same 24 tests separately. The cost
helper was changed first while the effect helper still received individual
fields; the effect helper was changed only after that suite passed. Both now
take capability plus mutable `PolicyDecisionV1`. The original and new assertions
are unchanged across the transformations. Root formatting passes on the final
candidate. The enclosing proof then passed with exit 0 using the supported
two-stage route (`cargo build --locked -p xtask`, then `./target/debug/xtask verify`):

- Attribution, root formatting, and warnings-denied workspace Clippy passed.
- All 36 workspace test targets passed: 2,006 passed, 0 failed, and 7 existing
  optional tests ignored. The separate request-contract run passed 203 tests.
- Site formatting and Clippy, 7 Rust tests, 18 Bun tests, and both reproducible
  edge builds passed. The reproduced digest remained
  `0bebb63577ce520c6b8d1a4af14446238fc748e5a8f348dfcb72c526aebb134b`.
- Bridge frozen installation/type generation/type checks/TypeScript and 3 Bun
  tests passed. Dependency advisories, bans, licenses, and sources passed;
  the full-history secret scan covered 856 commits with no leaks.
- Source/governance checks and the Linux x86_64 musl cross-build passed.

All 18 frozen input hashes, HEAD, source status, and the Git index matched
immediately after proof. Phase 3 is `done` for the two selected helper interfaces.
The original and expanded assertions, prior dirty work, and operator directive
remain preserved. Closing records were finalized after proof; verified source
and guidance bytes remain unchanged. The earlier hold receipt, intermediate test
logs, proof-input snapshot, and final result are retained in the task's `outputs/`
directory. The full proof log is
`/Users/star/Documents/Codex/2026-10-19/new-chat/outputs/cfctl-phase-3-enclosing-proof.log`.

## Safety Net Map

Only the behaviors listed below are pinned by this pass. Gaps stay outside the
scope of later refactoring until characterized; this is not a coverage claim
for all of cfctl.

| Module | Pinned behaviors | Test files | Gaps |
|---|---|---|---|
| `cfctl-planner::PolicyEngine::evaluate`: early guards | Selector ambiguity precedes dirty overlap, which precedes blocked adapter, contract gaps, and incremental-cost handling; early blocks retain one reason and no cost-ceiling flag. Read calls obey these guards too. | `crates/cfctl-planner/tests/policy.rs`: `selector_dirty_and_adapter_blocks_precede_contract_and_cost_checks`, `reads_still_obey_selector_dirty_and_adapter_blocks` | No claim that the planner validates every internally inconsistent capability field combination. |
| Contract admission boundary | Unknown cost, unsupported verification/rollback, and missing permission reasons remain ordered; unknown incremental cost sets the ceiling flag even on rejection. Existing tests retain incomplete/unsupported mutation rejection. | `policy.rs`: `mutation_contract_gaps_keep_their_order_and_unknown_cost_flag`, existing mutation-contract tests | Exhaustive validation of cost amounts/currencies, entitlement, and individual runtime contracts belongs to `cfctl-core`; not added here. |
| Read-only shortcut and charged metadata | GET/HEAD/OPTIONS with Read/ReadOnly metadata and no incremental cost remain automatic despite repository/resource counts and dependent/unmanaged configuration. Charged GET reads retain cost/risk/impact reason order, ceiling flags, and early-block precedence. Unknown non-incremental cost still reaches the read shortcut; ReadOnly/ScopedWrite without impact retains the existing automatic fallback reason. | `policy.rs`: `uncharged_reads_ignore_approval_only_impact_metadata`, `read_metadata_keeps_cost_risk_and_impact_decisions`, `charged_reads_keep_early_block_precedence_and_clear_ceiling` | The characterized synthetic metadata is pure planner behavior, not a guarantee of runtime capability validity. |
| Write impact policy | Zero or one affected repository permits an otherwise scoped reversible write; two require approval; resource count alone does not change that decision. Dependent or unmanaged configuration produces one shared reason, including when both are present. | `policy.rs`: `isolated_write_impact_thresholds_and_dependency_reasons_are_stable` | Actual workspace impact discovery and resource completeness are separate boundaries. |
| Effect, risk, adapter, and cost policy | Complete write contracts preserve automatic scoped reversible writes and approval for DataWrite/Spend/Destructive/ExternalCommunication/IdentityOrOwnership/Irreversible effects. Non-scoped known risks require approval for reversible writes; unknown risk blocks. Native/DynamicApi/DelegatedCli/GovernedUi share the same scoped-write policy. Incremental Spend has one cost reason. Non-mutating Spend pins all four known/incremental cost combinations and cost insertion order. Non-mutating Unknown effect/risk pins both reasons with and without incremental cost. | `policy.rs`: `complete_write_contract_keeps_effect_specific_decisions`, `reversible_write_risk_classes_keep_their_existing_approval_floor`, `supported_adapter_classes_share_the_same_isolated_write_policy`, `incremental_spend_has_one_cost_reason`, `non_mutating_spend_keeps_cost_guard_and_reason_order`, `non_mutating_unknown_effect_keeps_effect_and_risk_reasons`; existing cost tests and recovery unit test | Every risk/effect cross-product is not exhaustively enumerated. Adapter executability and exact approval are enforced outside this pure policy function. |
| Rollback admission and approval | Missing automatic strategy or missing/default manual warning blocks before known-cost approval, with no ceiling flag. A declared manual rollback permits admission but retains reversible-write approval for ScopedWrite/Read/CrossConfig risks, cost flags, and combined impact/risk reason order. | `policy.rs`: `missing_rollback_declaration_blocks_before_known_cost_approval`, `declared_manual_rollback_keeps_reversible_write_approval_and_order` | The planner samples core admission; it does not prove a manual recovery procedure or runtime compensation execution. |
| Combined decision contract | Known incremental cost, cross-repository impact, dependency impact, DataWrite effects, and CrossConfig risk accumulate in a fixed order, retaining schema version 1 and the ceiling flag. | `policy.rs`: `approval_reasons_accumulate_in_policy_hash_order`; shared assertion checks the complete `PolicyDecisionV1` | CLI plan persistence/replay, active policy bundles, drift, locks, and live execution are not exercised by these planner tests. |
| `xtask::local_guidance` inventory | The root-anchored operator note is a known exact path; the current repository ignore inventory is covered. Unknown exact Markdown paths are rejected, leading whitespace remains significant, and glob rules stay outside the exact-path inventory. Enclosing domain/archived-command checks passed with the newly inventoried note. | `xtask/src/local_guidance.rs`: all 5 tests, including extended `known_root_anchored_paths_are_covered`; successful enclosing proof | The directive's meaning and effect-specific authority remain outside this verifier change. |
| CLI runtime-lock observation fixture | Shared and unlocked states are distinguished from exclusive ownership, and dropping the exclusive guard permits shared observation again. Assertions run in an isolated child; timeout/failure cleanup and the one-test result are checked by the parent. | `crates/cfctl-cli/tests/cli/auth_import.rs`: `exclusive_lock_observation_rejects_shared_and_unlocked_states`, exercised within all 47 CLI tests | The failed parallel run's descriptor owner was not captured; controlled inheritance is a demonstrated mechanism, not attribution of that run. Production lock behavior is unchanged. |

## Characterization Backlog

- Phase 3 pins the selected charged-read, non-mutating Spend/Unknown, and
  missing/manual-rollback combinations. Extend characterization before changing
  an additional combination outside the Safety Net Map.
- Before changing admission logic, map the existing `cfctl-core` mutation-contract
  tests rather than duplicating that validator in planner fixtures.
- Before changing plan orchestration, pin policy tightening and policy-hash drift
  through the existing CLI plan tests. This pass preserves those consumers.

## CI Gates

The repository uses local proof; see [CONTRIBUTING.md](../CONTRIBUTING.md).
`cargo xtask verify` remains the authoritative enclosing gate. Focused planner
tests do not replace workspace lint/tests, site proof, security/governance checks,
or the Linux cross-build, and do not establish merge or release readiness.

On this host, Disk Guard reports `PATH_UNQUALIFIED` for the `xtask` Cargo alias.
Its documented route is to finish a guarded `cargo build --locked -p xtask`,
then execute `./target/debug/xtask verify` without an outer Cargo reservation.
Use the source owner's explicit native target/output variant where applicable.
Preserve existing reservations and obtain fresh admission for each build phase.
The phase tracker records the current enclosing-gate result.
