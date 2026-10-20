# Improve Code Quality Plan

## Context

Started 2026-10-19. The user selected cfctl, requested a bounded safety-net pass,
and explicitly prioritized consistency and preservation of existing behavior.
The selected module is `cfctl-planner::PolicyEngine::evaluate` in the canonical
Rust workspace. Baseline source is `main` at
`aaedc6f1b4d11c8ea41fb0ac440bec8ecfcb1b79`. At Phase 3 closure, additions
remained uncommitted; subsequent delivery commits are a separate history boundary.
Existing `.gitignore` and three runbook changes belong to prior work and are
preserved. Actual production load is unknown and is not needed for this pure
policy characterization slice.
Phase 1 completion also includes the user-authorized ignored-note inventory repair and
the bounded CLI fixture isolation needed for reliable enclosing proof. Planner
logic and production locking remain unchanged.

## Phase Status

| Phase | Skill | Status | Artifact | Date |
|---|---|---|---|---|
| 1 — Build the safety net | working-with-legacy-code (Phase 1 Brief fallback) | done | TESTING.md + TECH-DEBT.md (GATE) | 2026-10-19 |
| 2 — Make the code readable | clean-code (Phase 2 Brief fallback) | done | TECH-DEBT.md | 2026-10-19 |
| 3 — Apply named refactorings | refactoring-patterns (Phase 3 Brief fallback) | done | TECH-DEBT.md | 2026-10-20 |
| 4 — Reduce complexity | software-design-philosophy | deferred: no structural change selected | TECH-DEBT.md | |
| 5 — Draw the architecture boundary | clean-architecture | deferred: no architecture change selected | ARCHITECTURE.md | |
| 6 — Lock in the habits | pragmatic-programmer | deferred: habits phase not selected | TECH-DEBT.md | |
| 7 — Make it survive production | release-it | deferred: separate reliability scope and requirements needed | RELIABILITY.md | |
| 8 — Size for real load | system-design | deferred: load is not established | ARCHITECTURE.md + RELIABILITY.md | |
| 9 — Get the data layer right | ddia-systems | deferred: no datastore/concurrency change selected | ARCHITECTURE.md | |
| Optional — Domain language | domain-driven-design | deferred: no domain-model change selected | ARCHITECTURE.md | |

Statuses: pending · in-progress · awaiting-evidence · done · deferred: reason · skipped: reason

## Key Decisions

| Date | Phase | Decision | Rationale |
|---|---|---|---|
| 2026-10-19 | 1 | Select the small planner policy boundary over the highest-churn workspace loader. | Shared authority impact, bounded pure interface, and uncovered precedence/combination behavior; the recent workspace ownership changes already have focused regressions. |
| 2026-10-19 | 1 | Use the requested skill's Phase 1 Brief fallback. | The constituent `working-with-legacy-code` skill is unavailable. Existing public functions provide the seam; no production extraction is necessary. |
| 2026-10-19 | 1 | Initial slice: add tests and scoped records only. | The initial slice preserved current behavior and excluded refactors, defect fixes, dependency changes, installation, provider operations, and commits. The separately authorized follow-up is recorded below. |
| 2026-10-19 | 1 | Preserve exact reasons and ordering as well as approval outcomes. | The CLI uses the complete compiled decision in policy hashing; consistency extends beyond the disposition enum. |
| 2026-10-19 | 1 | Follow-up: repair the exact ignored-note inventory and rerun the enclosing proof. | The user explicitly authorized this narrow repair, required preservation of the directive and dirty work, and conditioned Phase 1 closure on a passing gate. |
| 2026-10-19 | 1 | Isolate the existing runtime-lock observation fixture after the rerun exposed a parallel-suite failure. | Standalone execution passed; controlled inheritance reproduced retained shared ownership. A child process preserves all assertions and bounded cleanup without changing production locking or serializing the whole suite. |
| 2026-10-19 | 2 | Limit changes to consistency and readability in the pinned planner implementation. | The user selected Phase 2 and required behavior, dirty-work preservation, and a passing enclosing proof before closure. |
| 2026-10-19 | 2 | Use the Phase 2 Brief fallback; apply three small source-backed improvements and defer helper-interface restructuring. | `clean-code` is unavailable locally. Shared reason text, consistent enum imports, and placing approval state after blocking guards improve reading without changing conditions or reason ordering. |
| 2026-10-19 | 2 | Keep readability scores as an assessment; retain the existing enclosing verifier as the gate. | No new automated score threshold or infrastructure was requested. All Phase 1 assertions remain unchanged. |
| 2026-10-19 | 2 | Close only after the enclosing proof passed and all 18 frozen inputs, HEAD, and source status matched. | The verifier exited 0 on the changed planner source; applied readability findings are closed and the helper-interface gap remains explicitly deferred. |
| 2026-10-20 | 3 | Characterize charged reads, non-mutating Spend metadata, and rollback combinations before simplifying the two helper interfaces. | The user selected this bounded structural pass and retained behavior, consistency, dirty-work preservation, and enclosing-proof requirements. |
| 2026-10-20 | 3 | Use the Phase 3 Brief fallback and Introduce Parameter Object with the existing `PolicyDecisionV1`. | `refactoring-patterns` is unavailable locally. Group the three mutable decision fields without adding a parallel type or changing the public API; run characterization first and tests between transformations. |
| 2026-10-20 | 3 | Preserve the active preview reservation and defer interface changes until characterization can run green. | Disk Guard returned `LANE_BUSY` for the planner test command: reservation `0079c90b68844b6cbdabf1390de61611` belongs to `/Users/star/dev/mln-research-site` and has unknown output-lane coverage. No test process was started. |
| 2026-10-20 | 3 | Resume after fresh admission; pin all new assertions on unchanged Phase 2 production source before restructuring. | Admission cleared without this task changing the preview or its reservation. The expanded planner suite passed 24 tests, including six new tests covering 31 cases. |
| 2026-10-20 | 3 | Pass the existing decision object to each helper, with focused tests between transformations. | Each helper now takes capability plus mutable `PolicyDecisionV1`. Both transformations passed all 24 planner tests; no new state type, condition, reason, ordering rule, or public interface was introduced. Enclosing proof remains required. |
| 2026-10-20 | 3 | Close only after the enclosing verifier exited 0 and preservation checks matched. | All 18 frozen inputs, HEAD, source status, and the Git index matched after proof. Workspace: 2,006 passed, 0 failed, 7 existing optional ignores; remaining request/site/bridge/security/governance/Linux stages passed. |

## Next Actions

- The initial planner baseline and expanded tests, focused lint, root formatting,
  and whitespace checks passed. The first two-stage proof passed workspace Clippy,
  then reported 1,999 tests passed, 1 failed, 7 ignored. The failing xtask
  guidance-inventory test concerns the earlier `/CLOUDFLARE.md` ignore rule;
  neither that rule nor its inventory was changed by that initial test-only pass.
- The user-authorized follow-up added `CLOUDFLARE.md` to the existing by-name
  inventory and extended the known-path fixture. All 5 focused guidance tests
  pass; the directive, ignore rule, planner tests, and prior runbook hashes are
  unchanged. The first follow-up run failed a different CLI lock-observation
  fixture before reaching xtask. That fixture is now isolated in a child test
  process; all 47 CLI integration tests pass without changing runtime locking.
  Three additional parallel CLI runs also passed 47/0 each.
- The final enclosing proof exited 0: attribution, formatting, workspace Clippy,
  2,000 workspace tests (7 opt-in ignored), the separate 203-test request contract,
  site Rust/Bun checks and reproduced edge builds, bridge checks, dependency and
  secret policy, source/governance, and Linux musl cross-build all passed.
  All 17 frozen input hashes, HEAD, and source status matched after the run.
  Phase 1 is closed for the bounded Safety Net Map; the two observed gate/fixture
  debt entries are closed. The earlier failures remain preserved in proof logs.
- Phase 2 is complete. Its baseline and changed planner suites passed all
  18 tests. Prior dirty code, guidance, directive, runbooks, and dependency locks
  remain unchanged; only planner implementation and these phase records changed.
  Its enclosing verifier exited 0: 2,000 workspace tests passed, 0 failed,
  7 existing optional tests ignored; all remaining request/site/bridge/security/
  source/Linux stages passed. All 18 frozen input hashes, HEAD, and source status
  matched after proof. Phase 2 was closed after those checks, with final evidence
  at `outputs/cfctl-phase-2-result.json` in the task workspace.
- Phase 3 characterization passed all 24 planner tests on unchanged Phase 2
  production source. Its six new tests pin 31 combinations; the existing 17
  integration tests remain byte-for-byte intact. Admission cleared on the user's
  requested recheck, and this task made no change to the preview or reservation.
- Both helper transformations passed the 24-test planner suite individually.
  The enclosing verifier then exited 0: 2,006 workspace tests passed, 0 failed,
  7 existing optional tests ignored; the remaining request/site/bridge/security/
  governance/Linux stages passed. All 18 frozen inputs, HEAD, source status, and
  the Git index matched immediately afterward. Phase 3 is complete for the
  selected helpers. Closing evidence is in the task workspace's
  `outputs/cfctl-phase-3-result.json`; later phases remain deferred.
