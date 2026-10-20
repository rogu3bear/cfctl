# Technical Debt

## Debt Ledger

This ledger starts with the bounded planner safety-net pass on 2026-10-19.
Entries distinguish coverage limits from an observed local gate inconsistency.
No behavior was silently repaired while adding characterization tests.

| Item | Location | Type | Risk | Effort | Priority | Status |
|---|---|---|---|---|---|---|
| Earlier ignored operator note was absent from the by-name guidance inventory | `.gitignore` `/CLOUDFLARE.md`; `xtask/src/local_guidance.rs:LOCAL_AGENT_FACING_NOTES` | Observed local gate inconsistency | The initial enclosing verifier failed `repository_exact_ignored_paths_are_covered`. | Small, user-authorized inventory repair | P1 | Closed: inventory and known-path fixture repaired; 5 focused tests and the full enclosing proof passed. Directive and prior dirty work preserved. |
| Runtime-lock observation shared a process with parallel subprocess-spawning tests | `crates/cfctl-cli/tests/cli/auth_import.rs` | Test fixture isolation | The next enclosing run failed exclusive acquisition; the unchanged test passed alone. Controlled descriptor inheritance reproduces retained shared ownership, but the original holder was not captured. | Small, isolate existing assertions with existing bounded child cleanup | P1 | Closed: existing assertions isolated; all 47 CLI tests, 3 additional parallel repeats, and the full enclosing proof passed. Production locking untouched. |
| Remaining charged-read, non-mutating Spend, and missing-rollback combinations | `crates/cfctl-planner/src/lib.rs`, `PolicyEngine::evaluate` | Characterization gap | A later policy refactor could change an unpinned decision or ceiling flag. | Small, before changing those branches | P1 when those branches change | Closed for the selected Phase 3 combinations: six new tests/31 cases passed on unchanged Phase 2 production source and after both helper transformations. The full enclosing proof passed. Broader combinations remain governed by the Safety Net Map. |
| Core admission validator is only sampled at the planner boundary | `cfctl-core::CapabilityV1::mutation_contract_gaps` | Coverage-map gap | Broadening the planner pass could create duplicate validation fixtures and inconsistent expectations. | Inspect existing core tests before choosing the next slice | P2 | Open; no core implementation changes authorized by this slice |
| CLI policy-hash lifecycle is outside the pure planner test boundary | `crates/cfctl-cli/src/runtime/plan_prepare.rs`, `plan_commands.rs` | Consumer coverage-map gap | Passing planner tests do not prove persistence, active bundle tightening, or replay/drift behavior. | Map existing CLI tests before a consumer change | P1 when those consumers change | Open; existing consumers preserved |
| Policy helpers take three related mutable outputs | `cfctl-planner::require_incremental_cost_approval`, `apply_effect_policy` | Readability/design debt | A future signature rewrite can separate disposition, reasons, and ceiling updates or change their order. | Small, after the remaining behavior combinations are pinned | P2 | Closed in Phase 3: Introduce Parameter Object using existing `PolicyDecisionV1`. Each helper takes two arguments; all 24 planner tests passed after each step and the full enclosing proof passed. |

## Smell Inventory

Phase 2 was limited to the planner behaviors already listed in the Safety Net Map.
Phase 3 established its new characterization before changing the helper interfaces.
Reason text and insertion order are consumer-visible policy-hash inputs.

| Smell | Location | Refactoring | Status |
|---|---|---|---|
| The incremental-cost reason was repeated in both insertion and deduplication code | `cfctl-planner/src/lib.rs`: incremental-cost and Spend policy | Name the identical text once as `INCREMENTAL_COST_REASON`; keep its bytes and every insertion position | Closed: 18 unchanged planner tests and the full enclosing proof passed |
| Adapter status used a qualified name while neighboring core enums used imports | `PolicyEngine::evaluate`: blocked-adapter guard | Import `AdapterStatus` with the other core enums | Closed: enclosing proof passed |
| Mutable approval accumulators appeared before the blocking checks that do not use them | `PolicyEngine::evaluate` | Initialize approval state after the existing blocking guards; explain the guard precedence and reason-order contract | Closed: predicates and branch order retained; enclosing proof passed |
| Two helpers expose four arguments, including three related mutable outputs | Incremental-cost and effect-policy helpers | Introduce Parameter Object using existing `PolicyDecisionV1`; preserve the cohesive ordered policy path | Done: both helpers now take two arguments; all 24 planner tests passed after each transformation, and the enclosing verifier exited 0 with frozen inputs unchanged. |

## Readability Assessment

ASSESSMENT on 2026-10-19 using the Phase 2 Brief fallback. Scores are qualitative
review judgments, not measured coverage or a new CI gate. The below-8 function
interface gap is explicitly recorded in the Smell Inventory and Debt Ledger.
Phase 2 closed only after the full enclosing verifier exited 0 and its frozen
inputs matched; the three applied findings above are complete.

| Discipline | Before / 10 | After / 10 | Evidence and limit |
|---|---|---|---|
| Naming | 8 | 9 | A named shared cost reason and consistent enum imports expose the same concepts consistently. |
| Function focus and arguments | 7 | 7 | At Phase 2 closure, public evaluation stayed cohesive and the two four-argument helpers remained deferred pending broader characterization. |
| Comments and intent | 7 | 9 | Two brief comments explain blocking precedence and why reasons retain insertion order. |
| Duplication and consistency | 7 | 9 | Both writers and the duplicate check use the same private reason constant. |
| Error handling | 9 | 9 | Typed blocked decisions retain specific reasons; core contract gaps are forwarded unchanged. No catch-and-ignore, null return, or contextless error was found in this pure module. |
| Formatting and flow | 8 | 9 | Blocking guards precede approval-state setup; the existing read shortcut and subsequent policy order stay intact. |

## Error-Handling Audit

The planner returns `PolicyDecisionV1`, not an exception or transport result.
Blocking conditions return explicit reasons, mutation contract gaps remain an
ordered vector, and unknown metadata retains its existing refusal or approval
handling. This pass introduces no new fallible operation, error translation,
catch, or nullable return. No error-handling repair was justified. The unpinned
cost/read/rollback combinations remained outside the Phase 2 change. Phase 3
adds assertions for them before any production transformation.

## Sprout / Wrap Register

None. Tests call the existing public planner API and reuse its current fixture.
No production wrapper, alternate policy implementation, or dependency seam was
introduced.

## Adopted Conventions

Preserve behavior before restructuring. Assert the complete policy decision when
order or flags affect the consumer's policy hash. Reuse the existing fixture and
assert successful contract admission before testing later policy decisions.
Record a newly established defect separately; a characterization expectation
does not approve that behavior as a desired future contract. Keep application
behavior changes separate from characterization and bounded verifier/harness
repairs. The Phase 1 continuation changed no runtime locking or planner logic.

Phase 2 conventions: import peer core enums consistently; define a repeated
policy reason once when both writing and matching it; place mutable state where
its policy stage begins; explain precedence rather than restating conditions.
Preserve literal reason bytes, insertion order, disposition, schema, ceiling
flags, public signatures, and all existing characterization assertions. Record
larger structural findings before changing interfaces. The existing enclosing
proof remains the completion gate.

Phase 3 preparation on 2026-10-20 appends six characterization tests. They cover
charged-read cost/risk/impact decisions and guard precedence, non-mutating Spend
cost gating and reason order, missing rollback declarations, declared manual
rollback, and the non-mutating Unknown effect/risk branch. Synthetic metadata
fixtures describe pure planner behavior, not provider executability. The new
assertions initially could not run because Disk Guard held build admission behind
an independently owned preview reservation. On the user's recheck, admission
cleared and all 24 planner tests passed on unchanged Phase 2 production source.
The named helper-interface finding is now closed after implementation and the
enclosing proof. The dated Phase 2 scores above remain historical assessments;
no new score threshold or gate was introduced.

The Phase 3 implementation groups disposition, ordered reasons, and cost-ceiling
state in the existing `PolicyDecisionV1`. The existing decision constructor
initializes the same automatic/empty/no-ceiling state after the unchanged
blocking guards. Each helper takes that value with the capability; all mutations
retain their conditions and positions. The public evaluation signature, read
shortcut, early blocks, schema version, literal reasons, insertion order, and
Spend deduplication are unchanged. The 24-test suite passed after the cost-helper
step and again after the effect-helper step. The full enclosing verifier exited
0: 2,006 workspace tests passed, 0 failed, 7 existing optional tests ignored;
request/site/bridge/security/governance/Linux checks passed. All 18 frozen input
hashes, HEAD, source status, and the Git index matched after proof. Phase 3 is
closed for the selected interfaces. These closing records were finalized after
the successful proof with verified source and guidance bytes preserved.
