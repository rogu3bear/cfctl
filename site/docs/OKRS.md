# Website OKRs — activation with retained operator control

Cycle: first production website release and four-week learning window.

## Objective

Make cfctl's governed operating model obvious enough that qualified Cloudflare operators can reach a verified first success without weakening credential, approval, or evidence boundaries.

## Key results

1. Every install, authentication, plan, approval, and verification command published by the site is extracted from or tested against the real CLI; target: 100% at launch.
2. Every production website deployment records the exact source SHA, reviewed plan, apply artifact, and authenticated live readback; target: 100% at launch.
3. Establish a privacy-preserving baseline for landing-page visit → install copy → `doctor` success → first live read during the first two weeks; set an outcome target only after the baseline and sample-quality review exist.
4. Run moderated first-use sessions with recruited Cloudflare operators and establish the baseline for “can explain why a mutation is not immediate and identify the verification evidence”; set the improvement target after the first round.
5. Record zero confirmed cases where ordinary cfctl credential use opens an unexpected platform-keyring prompt during the cycle; investigate every report against installed build identity and backend readback.

## Guardrails

- Do not increase activation by hiding approval, cost, permission, or failure states.
- Do not collect command bodies, account identifiers, secret-shaped values, or evidence contents as product analytics.
- Do not treat GitHub traffic, copied commands, or deployment success as proof of operator value.

## Owners and cadence

- Product/website owner: baseline collection and weekly learning review.
- Runtime owner: command-contract and installed-build ratchets.
- Release owner: exact-SHA plan/apply/live-read evidence.
- Review weekly; grade outcomes only after the cycle has data.
