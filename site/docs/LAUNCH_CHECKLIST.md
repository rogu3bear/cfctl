---
artifact: launch-checklist
version: "2.1"
created: 2026-08-15
status: in-progress
launch_candidate: cfctl 1.2.x public-launch closure
baseline_source_commit: ad2c71795952a8400d1d6ba128b3bac75e5e588a
baseline_source_tree: 6cdb6607330ba922d4e3a3a546d8c8cd4a7117ab
observed_installed_commit: ad2c71795952a8400d1d6ba128b3bac75e5e588a
candidate_binding: enclosing-clean-git-head-plus-terminal-receipt
---

# Launch checklist: cfctl public-launch closure

This checklist is the coordination spine for finishing cfctl as a publicly
operable product. It does not collapse source, local proof, review, release
publication, site deployment, OAuth promotion, or live readback into one state.
An unchecked item is not implied complete.

Status vocabulary: **Done** has current evidence for the row's full exit
condition; **Partially proven** has current evidence for only named proof planes;
**In progress** has an active owner; **Blocked** cannot meet its exit condition
yet; **Not started** has no current proof; **N/A** is intentionally out of launch
scope.

## Launch overview

| Field | Value |
|---|---|
| What | Close the remaining product, proof, distribution, website, support, and operational gaps around the current cfctl 1.2.x line |
| Proposed launch date | 2026-08-22 |
| Launch type | Major public-launch closure of an already published CLI |
| Launch owner | Operator |
| Delivery coordinator | Codex |
| Go/no-go decision maker | Operator |
| Current source and installed baseline | Observed 2026-08-15: remote `main` is exact merge `ad2c71795952a8400d1d6ba128b3bac75e5e588a`, tree `6cdb6607330ba922d4e3a3a546d8c8cd4a7117ab`, with ordered parents `ba1afa3658c381abf75563b67a57d09db6ca5cda` and `05c3b19a77f16aa3f403bf267cacff4b02a9d87a`. `/Users/star/.local/bin/cfctl` resolves to the same commit and reports v1.2.1. The exact baseline passed the repository's uncached local proof during canonical bootstrap, both doctors are green, historical-catalog compatibility is installed-adopted, and the refreshed installed catalog exposes the prior Pages deployment adapter. The enclosing clean Git object containing this checklist is the direct-upload repair candidate and needs its own proof/review/integration/install receipts. Public release, `cfctl.com` custom-domain closure, OAuth promotion, real provider mutation, platform/human acceptance, and release artifacts remain open |
| Current public release | Observed 2026-08-15: v1.2.1, published 2026-07-20; non-draft, non-prerelease, and unsigned by the repository's recorded operator decision |
| Explicitly separate protected actions | Merge, release publication, `cfctl.com` deployment/domain verification, permanent OAuth promotion, external announcements, and paid/provider mutations |

### Key stakeholders

| Function | Owner | Responsibility |
|---|---|---|
| Product and final decision | Operator | Scope, target date, exceptions, and final go/no-go |
| Engineering and coordination | Codex | P0 repairs, evidence binding, checklist maintenance, and handoff |
| Independent review | Independent reviewer | Exact-object review after full source proof |
| Linux credential proof | Linux verifier | Real Secret Service host verification required by issue #108 |
| Security, privacy, and legal | Operator or named delegate | Policy/link review and OAuth/privacy acceptance |
| Support and operations | Operator or named delegate | Support channel, incident owner, monitoring, and launch coverage |

## Engineering readiness

| Priority | Item | Owner | Due | Status | Exit evidence / dependency |
|---|---|---|---|---|---|
| Blocker | Resolve `cfctl catalog coverage --json` failure after a successful catalog sync | Codex | 2026-08-16 | Done through installed adoption | Exact remote and installed build `ad2c717…` loads authentic pre-field producer bytes without rewriting them, hydrates absent `max_source_bytes` to non-authorizing zero, rejects nonempty planning and execution at zero, and keeps explicit positive bounds hash-strict. Poisoned-network fresh-store reads preserved digest, size, mtime, and file set; stale, missing, malformed, and tampered stores fail closed |
| Blocker | Govern the native Git-integrated Pages production deployment through its real consumers | Codex | 2026-08-18 | Done through installed catalog adoption; provider proof open | Installed `catalog show` exposes `dynamic_api`, `cross_config`, `reversible_write`, bounded direct cost zero with downstream usage, exact returned-ID readback, required terminal verification, and unsupported automatic rollback. Installed `guide` is `available` with non-null bodyless `call` argv. Plan/run still consumes once and polls only the returned ID; failure or ambiguity requires rectification without replay. No real Pages plan, approval, write, or provider readback has occurred |
| Blocker | Repair direct-upload Pages admission and exact deployment verification | Codex + Independent reviewer | 2026-08-18 | Observed 2026-08-15: installed repair absent; this checklist candidate carries the source repair, later planes open | Installed `ad2c717…` allowed a bodyless POST for the AOS direct-upload project; operation `dc8c34c3-9791-484a-a175-c431349d78a5` failed before creation with Cloudflare HTTP 400/code 8000096 (`manifest` required), `performed:false`, no deployment ID or compensation, and production unchanged. The successor binds a deterministic artifact manifest and exact Wrangler producer, rejects bodyless/direct project mismatches before write, consumes once, and verifies only the provider-returned deployment ID. Source/full-gate/review/integration/install adoption must all be green before AOS creates a new operation |
| Blocker | Reconcile or close PR #136 without bypassing review/proof | PR #136 owner + Independent reviewer | 2026-08-17 | Done through final-main proof/adoption | PR #136 merged as `45e967bd…`; its code is an ancestor of exact final main `ad2c717…`, whose clean canonical bootstrap/full gate and installed adoption are green. GitHub's absent hosted review/check objects remain an evidence limitation, not a substitute for the repository's required local proof |
| Blocker | Run authoritative source proof on the final candidate | Codex | 2026-08-18 | Done on exact remote main | Canonical bootstrap ran `CARGO_GATE_RESULT_TTL_SECS=0 cargo xtask verify` on clean `ad2c717…` / `6cdb6607…` and exited 0, covering formatting, warnings-denied Clippy, workspace/request/catalog tests, two edge builds, policy/security scans, governance contracts, and the Linux musl cross-build |
| Blocker | Prove keyring 4 on a real Linux Secret Service host and close issue #108 | Linux verifier | 2026-08-18 | Blocked | Observed 2026-08-15: issue #108 is open, unassigned, and has no comments; real-host evidence is absent and macOS fallback-file proof is insufficient |
| Blocker | Obtain independent exact-object review after the final proof run | Independent reviewer | 2026-08-19 | Partially proven; one composite review remains | Independent reviews covered the Pages/reproducibility candidate, the authentic historical-catalog repair, and actual-main commit-sensitive adoption. Final `ad2c717…` ancestry, repair-owned file equality, installed bytes, and focused tests are bound, but one concise adversarial review of the complete final checklist claim remains required before release assembly |
| Blocker | Keep running, PATH, and source build identities aligned | Codex | 2026-08-19 | Done | `command -v`, realpath, version, doctor, and agents doctor all bind `/Users/star/.local/bin/cfctl` to v1.2.1 at exact remote-main `ad2c717…`; installed SHA-256 is `be13d74ffda19bb8259f9a035a295977bc662edd97a23b52384002dc2cb4bacc` and instruction drift is zero |
| Blocker | Make version/install copy single-sourced and drift-tested | Codex | 2026-08-18 | Done on remote main | Source proof enforces exact workspace-version pins and the current version in `QUICKSTART.md`; the negative drift contract intentionally pins v0.0.0 and requires the gate to reject it |
| Should | Assemble the four-platform unsigned release set reproducibly | Codex | 2026-08-20 | Not started | `cargo xtask assemble`; two builds per target, SPDX SBOMs, provenance, checksums, Homebrew formula; no upload |
| Blocker | Reconcile unsigned release policy with the executable publication lane | Codex + Operator | 2026-08-19 | Blocked on product/security decision | README, QUICKSTART, SECURITY, and CONTRIBUTING say published releases are unsigned by operator decision, but `cargo xtask publish` calls `verify_signed_release` and accepts only the signed artifact inventory. Choose signed publication, or implement and independently prove a checksum-only unsigned draft-upload lane that excludes the identity-verifying Linux installer; do not publish manually around the mismatch |
| Should | Remove or explicitly defer every launch-scoped TODO/known limitation | Codex + Operator | 2026-08-19 | Not started | Decision log names owner, consequence, and closure date for each accepted deferral |

## QA & testing

| Priority | Item | Owner | Due | Status | Exit evidence / dependency |
|---|---|---|---|---|---|
| Blocker | Complete formatting, warnings-denied Clippy, Rust tests, request contract, site proof, bridge proof, security/source contracts, secret scan, dependency policy, and Linux musl cross-build | Codex | 2026-08-18 | Done on exact remote main; checklist reconciliation reproof required | Canonical exact-main bootstrap completed the repository's uncached authoritative verification lane. Any commit that changes this checklist must rerun its focused documentation contract and the current-object gate before publication |
| Blocker | Add and pass a persistence-compatibility regression for the `max_source_bytes` catalog failure | Codex | 2026-08-16 | Done on exact remote main and installed consumer | A full `CatalogSnapshot::load` regression uses producer-authentic missing-field bytes and historical hash, preserves bytes without migration, hydrates zero, rejects positive-bound tampering and malformed input, and is joined to planning/execution zero-bound counterexamples. Exact `ad2c717…` focused tests passed 1/1 in catalog, core, and CLI suites |
| Blocker | Exercise OAuth callback missing, duplicate, empty, oversized, error, inert-rendering, clipboard-denial, expiry, background, bfcache, and no-JS states | Codex | 2026-08-18 | Partially proven | Rendered QA proves success/query scrubbing, missing, duplicate, oversized, provider error, inert markup, clipboard denial, two-minute expiry, pagehide, pageshow restoration, back-navigation clearing, and no-JS SSR non-rendering with zero console errors. Empty input remains unit-proven; a genuine hidden-tab transition and live edge-log/config readback remain open |
| Blocker | Complete keyboard, visible-focus, 320 px, 200% zoom, and reduced-motion review | Codex | 2026-08-18 | Partially proven | Rendered QA proves a visible focus ring, effective 355 px narrow reflow with no overflow, and reduced-motion clamping to `0.00001s`; source contracts cover 320 px, forced colors, and status regions. Retesting confirmed click focus reaches the Copy button, but the in-app backend does not advance Tab focus, its visibility override remains hidden, and raw CDP keyboard dispatch is unsupported. Full sequential keyboard order and native 200% zoom therefore remain unverified |
| Blocker | Run dependency and full-history secret scans on the final release tree | Codex | 2026-08-18 | Done on exact remote main; next candidate reproof required | Exact-main canonical verification passed advisories, bans, licenses, sources, and full-history Gitleaks. The checklist reconciliation creates a new object and must repeat the gate before it can become a release candidate |
| Should | Run account-backed token lifecycle smoke test in an explicitly disposable account | Operator + Codex | 2026-08-20 | Not started | Separate acknowledgement, reviewed permissions, mint/rotate/revoke/readback receipts; never part of automatic local proof |
| Should | Verify install paths on clean macOS arm64/x86_64 and Linux arm64/x86_64 environments | Platform verifiers | 2026-08-20 | macOS arm64 source/bootstrap proven; three targets open | Exact merged bytes are installed and both doctors pass on macOS arm64. Clean macOS x86_64 and Linux arm64/x86_64 direct-checksum/Homebrew or source paths remain unproven; the Linux installer remains intentionally unshipped while releases are unsigned |

## Design & UX

| Priority | Item | Owner | Due | Status | Exit evidence / dependency |
|---|---|---|---|---|---|
| Blocker | Confirm all public routes render useful SSR/no-JS content and honest blocked states | Codex | 2026-08-18 | Done for current rendered tree | Production-hash preview rendered `/`, `/start`, `/security`, `/privacy`, `/terms`, `/oauth/callback/`, and a real 404 with meaningful content, correct status behavior, no horizontal overflow, and no console errors; callback query values were absent from raw SSR and no-JS recovery was present |
| Blocker | Complete wide/narrow visual QA and interaction-state QA | Codex | 2026-08-18 | Partially proven | Desktop, effective 355 px narrow, focus, copy success, OAuth ready, clipboard denial, expiry, recovery, and 404 behavior were inspected; no clipping or runtime errors were found. Native 320 px, 200% zoom, complete keyboard traversal, copy-payload readback, and a second browser remain open |
| Blocker | Verify public copy against the exact CLI command tree and current capability semantics | Codex | 2026-08-18 | Done on exact main; checklist contract pending | Exact-main source contracts validate public examples, version pins, support stop conditions, and plan/apply/verification language. This checklist-bearing child must rerun the focused documentation contract and current-object gate |
| Should | Confirm favicon, metadata, social preview, and accessible naming | Codex | 2026-08-19 | Partially proven | Source/build contains favicon, manifest, title, description, theme color, landmark/heading labels, and accessible wordmark naming; social-card metadata and browser/live readback remain open |
| Nice | Produce a short product walkthrough | Product/Design owner | 2026-08-26 | Deferred | Does not delay launch; must show only shipped behavior |

## Marketing & communications

| Priority | Item | Owner | Due | Status | Exit evidence / dependency |
|---|---|---|---|---|---|
| Blocker | Finalize release notes that describe only shipped behavior and known limitations | Operator + Codex | 2026-08-20 | Not started | Final-SHA diff and verified limitations are the source; no OAuth or live-site claim before proof |
| Blocker | Decide whether this launch includes public site publication, release publication, both, or neither | Operator | 2026-08-19 | Blocked on decision | Each selected protected action receives its own reviewed authorization and readback |
| Should | Prepare announcement, repository README links, and installation copy | Product owner | 2026-08-20 | Not started | All links and checksums resolve; announcement remains draft until go decision |
| Should | Define first-use participant cohort and interview protocol | Product owner | 2026-08-21 | Not started | Named cohort, recruitment state, script, and consent/privacy posture |
| Nice | Prepare social/demo assets | Product/Design owner | 2026-08-26 | Deferred | No launch delay and no unsupported claims |

## Customer support

| Priority | Item | Owner | Due | Status | Exit evidence / dependency |
|---|---|---|---|---|---|
| Blocker | Name the public support channel and responsible owner | Operator | 2026-08-19 | Not started | Link is present and tested from the site and release |
| Blocker | Publish install/auth/catalog/plan troubleshooting guidance | Codex + Support owner | 2026-08-20 | Merged in source; public release/site linkage and owner acceptance open | The operator runbook consolidates install mismatch, no-profile/fallback-store, catalog drift, blocked capability, and uncertain-plan recovery responses; source proof enforces its no-secret, no-bypass, and no-replay language. A named support owner must accept it and the selected public surface must link it |
| Blocker | Define security escalation and response handoff | Security owner | 2026-08-20 | Partially proven | `SECURITY.md` exists; verify its destination and add named responder/coverage expectations |
| Should | Prepare concise support responses for install mismatch, credential fallback, catalog drift, blocked writes, and rectification | Support owner | 2026-08-21 | Merged; owner acceptance pending | The launch support triage table supplies copy-ready safe responses and stop conditions while prohibiting credentials, raw-provider bypass, plan edits, and replay |
| Should | Confirm launch-week support coverage | Operator | 2026-08-21 | Not started | Named primary and backup with availability window |

## Legal & compliance

| Priority | Item | Owner | Due | Status | Exit evidence / dependency |
|---|---|---|---|---|---|
| Blocker | Review privacy, terms, security, source-license, and support links/content | Operator or legal delegate | 2026-08-19 | Not started | Named reviewer confirms current text and destinations; this checklist is not legal approval |
| Blocker | Confirm OAuth callback data-handling and log-redaction posture | Security/privacy owner | 2026-08-19 | Partially proven | Source/build contracts prohibit SSR value rendering, storage, analytics, remote scripts/fetches, referrers, and callback caching; security/privacy acceptance and live log/config readback remain open |
| Blocker | Verify dependency licenses and notices | Codex + reviewer | 2026-08-18 | Partially proven | Authoritative local dependency advisories, bans, licenses, and sources checks passed; release notices/artifacts and named-reviewer acceptance remain open |
| Blocker | Confirm accessibility launch acceptance | Operator + reviewer | 2026-08-19 | Not started | Keyboard/zoom/reduced-motion results reviewed; any accepted exception has owner and deadline |
| Should | Decide whether permanent public OAuth is in this launch | Operator | 2026-08-19 | Blocked on decision | Promotion is a separate explicit transaction; publishing `cfctl.com` does not enable OAuth |

## Operations & infrastructure

| Priority | Item | Owner | Due | Status | Exit evidence / dependency |
|---|---|---|---|---|---|
| Blocker | Resolve and authenticate the exact Cloudflare account/site/Worker/domain target | Operator + Codex | 2026-08-20 | Historical Worker target proven; current launch identity open | A separately governed transaction previously bootstrapped `cfctl-site`, promoted one exact Worker version to 100%, and read back its `workers.dev` routes. Rebind the current service/version/account before reuse; that historical receipt does not identify a deployment of `ad2c717…` or the checklist successor |
| Blocker | Produce and review the exact site mutation plan | Codex + Operator | 2026-08-20 | Not started for current source | The previous Worker plan is consumed historical evidence. A current-source site launch needs a new plan with exact artifact, operation ID, account/targets, cost, permissions, verification, compensation, and warnings |
| Blocker | Approve and run only the reviewed operation ID if site launch is selected | Operator | 2026-08-21 | Blocked on scope decision and new plan | `plans approve --yes` then `plans run`; approval does not cover OAuth or release publication and no prior consumed operation may be replayed |
| Blocker | Perform authenticated post-deployment readback | Codex | 2026-08-21 | Historical workers.dev readback only | The prior deployed artifact returned HTTP 200 for `/`, `/start`, and `/oauth/callback`. Current-source route, source marker, security/cache headers, critical copy, 404, and callback policies remain unverified |
| Blocker | Verify custom domain, DNS, TLS, and publisher-domain ownership | Codex + Operator | 2026-08-21 | Blocked | The prior governed domain inventory returned no `cfctl.com` custom domain and lacked DNS Read. Current direct DNS/HTTPS checks still cannot resolve `cfctl.com`; require a credential-correct governed DNS/domain read before making an absence, outage, or ownership claim |
| Blocker | Test rollback using the previous known-good artifact/route plan | Codex + Operator | 2026-08-21 | Not started | Timed rehearsal succeeds without weakening plan/approval controls |
| Blocker | Name incident commander and on-call backup | Operator | 2026-08-20 | Not started | Names, channel, severity thresholds, and response window documented |
| Should | Verify release artifact retention and recovery copies | Operations owner | 2026-08-20 | Not started | Previous known-good binaries, checksums, provenance, and site artifact remain retrievable |

## Analytics & monitoring

| Priority | Item | Owner | Due | Status | Exit evidence / dependency |
|---|---|---|---|---|---|
| Blocker | Keep the approved launch analytics posture explicit | Operator | 2026-08-19 | Done for current source | No behavioral analytics; any later proposal requires event content, retention, consent, and prohibited identifiers review |
| Blocker | Define content-free operational health signals and alerts | Operations owner | 2026-08-20 | Not started | Availability, error rate, latency, deployment identity drift, and certificate expiry thresholds with owners |
| Blocker | Ensure OAuth callback queries are excluded/redacted from all logs and observability | Security + Operations owners | 2026-08-20 | Partially proven | Source strips callback queries from browser history and disables site-controlled analytics/storage/remote calls; bounded edge-log test and live observability configuration/readback remain open |
| Should | Baseline install-to-first-read success and support volume without behavioral tracking | Product owner | 2026-08-21 | Not started | Manual first-use protocol and content-free aggregate rubric approved |
| Should | Schedule T+1 and T+7 review | Operator | 2026-08-21 | Not started | Calendar owners and evidence inputs named |

## Go/no-go criteria

### Must have — launch blockers

- [x] Exact remote main `ad2c717…` / `6cdb6607…` is clean, uncached full-gate green, remotely read back, and installed with byte/build identity proof.
- [ ] This factual checklist reconciliation is a separate exact object; before merge it needs its focused documentation contract, uncached current-object gate, independent adversarial review, ordinary PR publication, and remote merge/readback. The repository deliberately has no hosted CI requirement, so absent GitHub checks are not substituted for or added to the local proof contract.
- [x] PR #136 is merged and its exact merge commit is identified; its unreviewed code remains inside the final-tree review scope.
- [x] The final installed candidate's historical persisted-catalog coverage/read path passes without hidden sync, and a controlled official refresh leaves Pages show/guide available.
- [ ] Before publication, attach an uncached `cargo xtask verify` receipt for the exact clean checklist-bearing candidate with no weakened gate or skipped assertion; the `ad2c717…` receipt becomes historical for any changed tree.
- [ ] Issue #108 has current real-Linux Secret Service evidence or the release is explicitly held.
- [ ] All public commands/copy, OAuth callback security cases, keyboard/zoom/reduced-motion cases, and dependency/secret scans pass.
- [ ] Privacy, terms, security, license, accessibility, support, and incident ownership are accepted by named owners.
- [ ] Reproducible release artifacts and a tested rollback are available.
- [ ] The operator resolves the unsigned-policy/publish-command mismatch: either approve signed release posture and identities, or merge a proven checksum-only unsigned draft-upload lane before creating release assets.
- [ ] Every selected protected action has exact authorization, successful execution evidence, and its own readback.
- [ ] No P0/P1 defect remains open; accepted lower-severity deferrals have owner, consequence, and closure date.
- [ ] The Pages direct-upload P0 is merged and installed with artifact, producer, project-mode, replay, exact-ID, terminal polling, and rectification proofs; only then may the AOS owner prepare a brand-new provider operation.

### Should have

- [ ] Clean-environment install checks pass across the four supported targets.
- [ ] Account-backed disposable token lifecycle smoke test passes under its separate acknowledgement gate.
- [ ] Release notes, announcement, troubleshooting macros, and first-use protocol are ready.
- [ ] Operational dashboard/alerts and launch-week coverage are active.

### Nice to have

- [ ] Short walkthrough/demo asset.
- [ ] Social launch assets.
- [ ] Post-launch case study plan.

## Critical path to release readiness

Each edge starts only after its dependency is terminal. Passing one edge grants
no authority for the next protected action.

| Order | Edge | Entry condition | Exit evidence | Authority / non-effects |
|---|---|---|---|---|
| 1 | Close, publish, integrate, and install the current CLI repairs | Historical source candidate green | **Done:** PRs #139, #141, and #140 merged; remote main is `ad2c717…`; canonical exact-main bootstrap/full gate passed; installed bytes and both doctors bind the same commit; historical-catalog and Pages installed consumers are green | No provider write, release publication, site update, or OAuth promotion occurred |
| 2 | Integrate and install the direct-upload repair plus current checklist | Exact `ad2c717…` baseline; failed operation preserved and closed | Clean logical commits, focused direct-upload/checklist contracts, uncached `cargo xtask verify`, independent exact-object `REVIEW_GREEN`, ordinary PR/merge readback, exact-byte installation, catalog refresh, both doctors, and installed no-write admission proof | No AOS deployment, provider write, release publication, site update, or OAuth promotion |
| 3 | Prove one fresh AOS direct upload through the installed governed path | Edge 2 green; AOS owner separately dispatches a brand-new exact operation | Artifact and producer manifest, direct-project admission, approval/run receipt, provider-returned deployment ID, exact terminal production readback, unchanged custom-domain/DNS/secret state, and no replay of `dc8c34c3…` | One exact AOS Pages deployment only; no raw Wrangler/API/dashboard bypass |
| 4 | Close platform and human launch blockers | Edge 3 green | Real Linux Secret Service receipt closes or explicitly holds issue #108; remaining three platform install checks; native keyboard/320 px/200% zoom/reduced-motion acceptance; named security/privacy/legal/support/incident owners; OAuth and site scope decisions | Human acceptance is recorded, not inferred from source tests |
| 5 | Resolve release-distribution posture | Edge 4 disposition | Operator selects signed or unsigned posture. Signed posture supplies exact signing/notary/Sigstore identities; unsigned posture first gains a reviewed executable checksum-only upload lane consistent with README/QUICKSTART/SECURITY and excludes `install.sh` | No asset upload or draft publication |
| 6 | Assemble release evidence | Exact merged/adopted source and edge 5 posture | `cargo xtask assemble` produces two-build reproducibility, four target binaries, SPDX SBOMs, provenance, checksums, and Homebrew formula; artifact inventory review passes | No signing or upload; unsigned releases do not ship the identity-verifying Linux installer |
| 7 | Sign only if selected | Edge 6 green and explicit signing/notarization authority plus identities | If signed posture is selected, `cargo xtask release` binds signatures, notarization, provenance, checksums, and the exact four-platform set. If unsigned posture is selected, this edge is recorded N/A by the operator | No GitHub publication or announcement |
| 8 | Publish the CLI release | Edge 6 and any selected edge 7 green; explicit release-publication authority | Exact tag and empty draft bind the release commit; only the posture-appropriate immutable assets upload; checksum/provenance readback and clean-environment install verification pass before the operator makes the draft public | Does not publish the website or promote OAuth |
| 9 | Publish `cfctl.com` if selected | Site scope selected; exact account/service/domain reads and reviewed plan exist | Exact plan approval/run receipts, authenticated route/source/header/content/404/callback readback, DNS/TLS/domain verification, and timed rollback rehearsal | Site transaction only; OAuth remains separate |
| 10 | Promote OAuth if selected | OAuth scope selected and security/privacy acceptance complete | Separately reviewed promotion plan, callback/provider configuration readback, redacted log verification, and tested revoke/disable compensation | Does not alter CLI release or site beyond the exact OAuth plan |
| 11 | Go live and observe | All selected blocker edges green; operator records go | Go/no-go decision, announcement identity, monitoring/on-call activation, T+1/T+7 schedule, and content-free health/support receipts | Any failed readback invokes the rollback plan and freezes announcements |

## Rollback plan

### Trigger conditions

- Published checksum, provenance, or binary identity does not match the approved release commit.
- P0/P1 credential, authorization, secret-leakage, plan-binding, execution, or verification defect is discovered.
- `cfctl.com` critical route, security header, OAuth callback, or install path fails live verification.
- Error rate exceeds 2% for a critical command/path over 15 minutes, or availability falls below 99% over 15 minutes.
- Operator or incident commander cannot establish current deployed/source identity.

### Rollback steps

1. Stop announcements and new promotion actions; record the exact failing evidence and time.
2. For the site, run the pre-reviewed compensating plan or restore the previous known-good deployment artifact and route bindings through cfctl's plan lifecycle.
3. For a release, keep or return the GitHub release to draft/non-latest as supported; do not overwrite published assets. Publish a new corrected version only after fresh proof.
4. Revoke or disable any newly promoted OAuth client/route through its separately reviewed compensation plan; never expose or log client secrets.
5. Run authenticated readback for the compensated state, communicate the incident through the named support channel, and open a bounded corrective issue.

### Rollback owner

Operator (decision and approval) with Codex (evidence, plan preparation, and verification).

### Rollback time objective

- Announcement freeze: 5 minutes.
- Site traffic rollback after approved compensation exists: 15 minutes.
- OAuth disable/revoke after approved compensation exists: 15 minutes.
- Corrected CLI release: no artificial SLA; remain no-go until full proof repeats.

## Check-in schedule

| Checkpoint | Date | Attendees | Decision/evidence |
|---|---|---|---|
| P0 triage | 2026-08-15 | Operator, Codex | Coverage persistence bug, PR #136, source-proof environment, Linux verifier |
| T-7 readiness review | 2026-08-16 | All named owners | Owners accept dates; P0 fixes and proof hosts are active |
| T-4 proof review | 2026-08-18 | Engineering, Linux verifier, reviewer | Terminal source/Linux evidence and remaining defects |
| T-2 go/no-go | 2026-08-20 | Operator, Engineering, Security, Operations | All blockers green; exact protected actions selected |
| Launch-day sync | 2026-08-22 | Operator, Codex, Operations, Support | Final identities, approvals, apply/publish status, live readback |
| T+1 review | 2026-08-23 | All named owners | Incidents, support findings, identity/availability readback |
| T+7 review | 2026-08-29 | Product, Engineering, Operations | First-use findings, deferred work, launch outcome |

## Open issues

| Issue | Owner | Due | Status | Impact / next action |
|---|---|---|---|---|
| Historical D1-import plans lacked the later `max_source_bytes` field | Codex | 2026-08-16 | DONE THROUGH INSTALLED ADOPTION | PR #141 merged the authentic-producer-hash repair; exact remote/installed `ad2c717…` reads the pre-field store without rewrite, hydrates zero, rejects nonempty zero-bound use, and preserves current positive-bound hash strictness |
| AOS direct-upload project received a bodyless Pages deployment request | Codex + Independent reviewer | 2026-08-18 | Observed 2026-08-15: P0 repair not yet installed; source candidate present | The closed operation reached no creation boundary and left production unchanged, but proves the installed carrier admitted the wrong project/request combination. Finish the deterministic artifact/producer and project-kind repair, exact-object proof/review, merge/install adoption, then hand the exact installed identity back for a fresh AOS operation; never replay the closed operation |
| Sandbox cannot connect to the peer-owned configured `sccache` daemon | Codex + environment owner | 2026-08-16 | Environment limitation; proof path established | One restricted focused rerun hit `sccache: Operation not permitted`; the pinned raw toolchain then ran the exact named tests without source or assertion changes. Canonical exact-main bootstrap separately ran the repository gate successfully |
| GitHub records no hosted checks or review objects on PRs #139-#141 | Independent reviewer | 2026-08-17 | Not a repository CI blocker; evidence-plane limitation retained | README states the tracked local pre-push proof is authoritative and no hosted CI service is required. Exact local gates, independent reviews, merge/readback, and installed adoption are recorded separately; GitHub mergeability alone is never treated as review |
| GitHub issue #108: real Linux Secret Service proof | Linux verifier | 2026-08-18 | BLOCKER | Run the isolated security-layer verification on a real host and attach exact evidence |
| Public OAuth is disabled and no current profile is selected | Operator | 2026-08-19 | Decision blocker only if OAuth is launch scope | Choose scoped-token-only launch or authorize a separate permanent OAuth promotion campaign |
| Current `cfctl.com` custom-domain state is unresolved | Codex + Operator | 2026-08-20 | BLOCKER if site is launch scope | Historical `workers.dev` publication is verified, but the prior domain inventory returned zero custom domains and lacked DNS Read. Current DNS/HTTPS resolution still fails. Obtain a credential-correct governed domain/DNS read before a site launch claim |
| Unsigned release policy has no matching automated publication lane | Codex + Operator | 2026-08-19 | BLOCKER | `cargo xtask publish` requires `verify_signed_release`, signed provenance/checksums, macOS identity, and the signed inventory, while public docs declare unsigned releases. Select signed posture or implement/prove an unsigned empty-draft upload path; do not use manual upload as an undocumented bypass |
| Support, incident, legal/privacy, and accessibility owners are unnamed | Operator | 2026-08-19 | BLOCKER | Assign named people or explicitly retain each role |

## Current evidence snapshot

- **Source and ancestry:** observed remote `main` is clean merge
  `ad2c71795952a8400d1d6ba128b3bac75e5e588a`, tree
  `6cdb6607330ba922d4e3a3a546d8c8cd4a7117ab`, with ordered parents
  `ba1afa3658c381abf75563b67a57d09db6ca5cda` and
  `05c3b19a77f16aa3f403bf267cacff4b02a9d87a`. PR #139 merged Pages governance
  and reproducible edge-tool selection; PR #141 merged authentic historical
  catalog hash compatibility; PR #140 merged Worker plan-set snapshot identity.
  The reviewed historical repair head `ce21bf7815b987d73e79f1e2e46b53a4a06be400`
  is an ancestor, and its two repair-owned files are byte-identical in final
  main. The peer-owned canonical checkout remains separately at `e584eaee…`
  with the same six modified files and was not normalized.
- **Installed runtime:** `command -v` and realpath both resolve
  `/Users/star/.local/bin/cfctl`; SHA-256 is
  `be13d74ffda19bb8259f9a035a295977bc662edd97a23b52384002dc2cb4bacc`.
  Version, doctor, and agents doctor bind v1.2.1 to exact `ad2c717…` with
  healthy self/PATH identity and zero instruction drift.
- **Historical catalog consumer:** an authentic pre-field fixture with 3,440
  capabilities, recursively absent material `max_source_bytes`, and digest
  `39d963f82985778dec492e0389bc1a7c71259bb237912e3e6a7d5e9caf6e652f`
  loads through the installed binary under poisoned networking without changing
  digest, size, mtime, or file set. Typed hydration yields zero; exact-main tests
  reject every nonempty planning and execution attempt at zero. Historical and
  positive-bound tampering fail content-hash validation; stale and missing
  stores attempt the official refresh and fail against the poisoned proxy
  without rewriting or creating a catalog.
- **Current installed catalog:** the pre-refresh real store was preserved as
  `catalog-v1.previous.json` at exact digest
  `fa4ad3100e9a0435ffd594fdd4c6239a8c9f7658fb9f086548735515e9fba7a8`.
  A separately authorized official refresh produced schema
  `sha256:d0ff1c7f24a8aa532675acbc99c45c2bd8e565f3184c3b1f013c1e36b2926598`
  and 3,387 capabilities; the count changed from the earlier upstream snapshot
  and is recorded rather than normalized away. Subsequent poisoned-network reads
  preserve the refreshed digest and expose Pages as `dynamic_api`/`available`
  with exact returned-ID verification and non-null call argv. Current D1 keeps
  explicit `max_source_bytes=67108864`.
- **Local proof and review:** canonical bootstrap ran the uncached full source
  lane on exact clean `ad2c717…` before installing it. Focused exact-main catalog,
  core, and CLI regressions each passed 1/1 after installation. Independent
  adversarial reviews separately confirmed the Pages/reproducibility candidate,
  actual-main commit-sensitive provenance and plan drift, and the authentic
  historical repair. This checklist changes the tree and therefore needs its
  own current-object gate and one composite review; prior receipts remain
  historical for the new object.
- **Hosted source:** observed 2026-08-15, remote `main` is `ad2c717…`; PRs #139,
  #140, and #141 are merged. GitHub records no review objects or hosted checks
  on those PRs. That is retained as a hosted evidence limitation, while README's
  repository doctrine explicitly makes the tracked local pre-push lane
  authoritative and does not require GitHub Actions. The latest public release
  is still non-draft, non-prerelease v1.2.1 from 2026-07-20. Issue #108 remains
  open, unassigned, and without comments or real-Linux evidence.
- **Release distribution:** source doctrine says current public releases are
  unsigned, using reproducible double-builds, SHA256SUMS, SPDX SBOMs, and
  commit-bound provenance. The executable `cargo xtask publish` path accepts
  only a signed artifact set after `verify_signed_release`. This mismatch is a
  launch blocker until signed posture is selected or a checksum-only unsigned
  publication path is implemented and reviewed. No new four-platform artifact
  set, tag, draft, upload, or publication has been created.
- **Authentication and human acceptance:** 19 profiles exist, no current profile
  is selected, the active backend is `fallback_file`, and public OAuth remains
  disabled. Linux Secret Service, native sequential keyboard, native 200% zoom,
  genuine hidden-tab behavior, legal/privacy/accessibility acceptance, support
  owner, incident commander, on-call backup, and release posture decision remain
  open.
- **Site and live edge:** a historical governed transaction bootstrapped and
  promoted one exact `cfctl-site` Worker version; its `workers.dev` `/`, `/start`,
  and `/oauth/callback` routes returned HTTP 200. It does not prove deployment of
  current source. The prior domain inventory found no `cfctl.com` custom domain
  and the profile lacked DNS Read; current direct DNS/HTTPS resolution still
  fails. No current-source site plan/apply/readback, custom-domain/TLS proof,
  OAuth promotion, or live log-redaction proof exists.
