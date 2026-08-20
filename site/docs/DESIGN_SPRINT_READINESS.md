# Design sprint readiness

Verdict: **Implemented direction / conditional validation**. Use a narrow
render-and-test loop against the current source and acceptance criteria.

## Ready

- A bounded surface and primary job are defined.
- Existing product semantics and release doctrine are inspectable.
- A working cargo-leptos/Workers template proves feasibility.
- Acceptance criteria and edge cases can anchor review.
- The owner has asked for a materially improved, de-templated site.
- The implemented source and styles provide a concrete wide/narrow candidate;
  a separate prose design-authority selection is no longer an entry gate.

## Missing

- No validated user research or current funnel baseline.
- No named decider, recruited test participants, or scheduled test window.
- The Leptos Design Studio's required Creative Production and Product Design stages are unavailable in the installed tool set.
- The runtime choice is closed for the first production launch: server-rendered Leptos runs on a Worker with Workers Assets. Pages would require a separate static/runtime architecture decision.

## Recommendation

Do not run a five-day broad sprint or reopen an abstract design-selection
stage. Review the implemented landing, quickstart, and authority lifecycle at
wide and narrow viewports against `ACCEPTANCE_CRITERIA.md`, then use a focused
correction/test loop. Recruit 5–8 representative operators for first-use
evaluation before making validated comprehension or activation claims.

## Entry criteria

- The exact source candidate and acceptance criteria are bound for rendered
  review.
- Owner accepts Workers Assets as canonical, or chooses Pages with the corresponding CSR/static scope change.
- Participant/reviewer plan exists.
- No open high-risk security or credential issue.

## Exit criteria

- Complete wide/narrow design coverage, not hero-only.
- At least one round of observed comprehension and first-read tasks.
- Decision log records accepted tradeoffs and remaining hypotheses.
