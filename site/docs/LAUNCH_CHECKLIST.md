---
artifact: launch-checklist
version: "2.0"
created: 2026-08-15
status: in-progress
launch_candidate: cfctl 1.2.x public-launch closure
proven_parent_commit: c3eb4bf51e588c37ff16ef10ad98795904323b96
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
| Current source candidate | Proven parent `c3eb4bf51e588c37ff16ef10ad98795904323b96`, tree `79134763c34ecf895265e2bd7baff1d58f184ee1`, directly based on observed `origin/main` `45e967bd55049685ab06b0109722354262db6089`. That parent passed the uncached authoritative full gate, fresh catalog consumer proof, historical-store compatibility read, and independent `REVIEW_GREEN`. This factual checklist reconciliation is a separate one-commit child; its exact identity is the clean Git HEAD containing this file and requires its own terminal gate/review receipt before publication. Push, hosted review, merge, installation, and release remain open |
| Current public release | Observed 2026-08-15: v1.2.1, published 2026-07-20; non-draft and non-prerelease |
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
| Blocker | Resolve `cfctl catalog coverage --json` failure after a successful catalog sync | Codex | 2026-08-16 | Done in source candidate; installed adoption open | Exact candidate `c3eb4bf…` reads an isolated copy of the real 3,440-capability historical store, while missing `max_source_bytes` decodes to zero and remains non-authorizing at planning and execution. The installed `45e967bd…` binary is unchanged; installation and PATH readback remain separate |
| Blocker | Govern the native Git-integrated Pages production deployment through its real consumers | Codex | 2026-08-18 | Done in proven parent; child reproof required | Fresh `catalog sync` feeds `catalog show` and `guide`; guide emits the exact bodyless `call` argv, call creates a plan, `plans run` consumes it once, and the verifier polls only the returned deployment ID. `active`/`idle` continue within the fixed bound; exact project/production `success` passes; failure, cancellation, unknown state, identity drift, provider error, or timeout/exhaustion fails verification and requires rectification without replay. Automatic rollback remains unsupported and cannot erase the deployment, reverse Functions side effects, or refund usage. Installed adoption and a real provider write/readback remain open |
| Blocker | Reconcile or close PR #136 without bypassing review/proof | PR #136 owner + Independent reviewer | 2026-08-17 | Done for local final-tree proof | PR #136 merged to `origin/main` as `45e967bd…` on 2026-08-15 with no hosted review decision or checks. Its code and the repair are now covered together by the clean `c3eb4bf…` full gate and independent exact-object review |
| Blocker | Run authoritative source proof on the final candidate | Codex | 2026-08-18 | Done | `CARGO_GATE_RESULT_TTL_SECS=0 cargo xtask verify` exited 0 on clean commit `c3eb4bf…`, tree `79134763…`, covering formatting, warnings-denied Clippy, all workspace tests, site proof, reproducibility, policy/security scans, governance contracts, and Linux musl cross-build |
| Blocker | Prove keyring 4 on a real Linux Secret Service host and close issue #108 | Linux verifier | 2026-08-18 | Blocked | Observed 2026-08-15: issue #108 is open, unassigned, and has no comments; real-host evidence is absent and macOS fallback-file proof is insufficient |
| Blocker | Obtain independent exact-object review after the final proof run | Independent reviewer | 2026-08-19 | Done | Independent read-only review bound `c3eb4bf…` / `79134763…`, reran the focused compatibility, catalog, and runtime tests, found no findings at any severity, and returned `REVIEW_GREEN` |
| Blocker | Keep running, PATH, and source build identities aligned | Codex | 2026-08-19 | Source candidate ready; adoption blocked | The candidate binary self-reports `c3eb4bf…`; `cfctl` on PATH still reports v1.2.1 at `45e967bd…` and its Pages guide remains blocked with five missing contract classes and `call_argv=null`. Recheck only after hosted merge and separately authorized installation |
| Blocker | Make version/install copy single-sourced and drift-tested | Codex | 2026-08-18 | Done in proven parent | Source proof enforces exact workspace-version pins and the current version in `QUICKSTART.md`; `tests::quickstart_release_download_path_fails_closed_on_version_drift` intentionally pins v0.0.0 and proves the gate rejects it with the required current path |
| Should | Assemble the four-platform unsigned release set reproducibly | Codex | 2026-08-20 | Not started | `cargo xtask assemble`; two builds per target, SPDX SBOMs, provenance, checksums, Homebrew formula; no upload |
| Should | Remove or explicitly defer every launch-scoped TODO/known limitation | Codex + Operator | 2026-08-19 | Not started | Decision log names owner, consequence, and closure date for each accepted deferral |

## QA & testing

| Priority | Item | Owner | Due | Status | Exit evidence / dependency |
|---|---|---|---|---|---|
| Blocker | Complete formatting, warnings-denied Clippy, Rust tests, request contract, site proof, bridge proof, security/source contracts, secret scan, dependency policy, and Linux musl cross-build | Codex | 2026-08-18 | Done on proven parent; child reproof required | Terminal authoritative gate exited 0 on `c3eb4bf…`; it included 171 catalog tests, 146 Cloudflare request tests, OAuth callback tests 5/5, reproducible edge hash `4f6d5136…`, dependency/license/source policy, a 474-commit secret scan, and Linux musl cross-build. This checklist-only child needs its own current-object gate |
| Blocker | Add and pass a persistence-compatibility regression for the `max_source_bytes` catalog failure | Codex | 2026-08-16 | Done on proven parent; focused child reproof required | Missing historical bound decodes to zero for reads; explicit planning and execution counterexamples both reject the zero bound. The proven parent also passed coverage against an isolated copy of the real historical store |
| Blocker | Exercise OAuth callback missing, duplicate, empty, oversized, error, inert-rendering, clipboard-denial, expiry, background, bfcache, and no-JS states | Codex | 2026-08-18 | Partially proven | Rendered QA proves success/query scrubbing, missing, duplicate, oversized, provider error, inert markup, clipboard denial, two-minute expiry, pagehide, pageshow restoration, back-navigation clearing, and no-JS SSR non-rendering with zero console errors. Empty input remains unit-proven; a genuine hidden-tab transition and live edge-log/config readback remain open |
| Blocker | Complete keyboard, visible-focus, 320 px, 200% zoom, and reduced-motion review | Codex | 2026-08-18 | Partially proven | Rendered QA proves a visible focus ring, effective 355 px narrow reflow with no overflow, and reduced-motion clamping to `0.00001s`; source contracts cover 320 px, forced colors, and status regions. Retesting confirmed click focus reaches the Copy button, but the in-app backend does not advance Tab focus, its visibility override remains hidden, and raw CDP keyboard dispatch is unsupported. Full sequential keyboard order and native 200% zoom therefore remain unverified |
| Blocker | Run dependency and full-history secret scans on the final release tree | Codex | 2026-08-18 | Done on proven parent; child reproof required | Advisories, bans, licenses, and sources passed; Gitleaks scanned 474 commits / 9.36 MB with no leaks on clean `c3eb4bf…`. The release object changed for this checklist reconciliation, so the current-object gate must repeat the scan |
| Should | Run account-backed token lifecycle smoke test in an explicitly disposable account | Operator + Codex | 2026-08-20 | Not started | Separate acknowledgement, reviewed permissions, mint/rotate/revoke/readback receipts; never part of automatic local proof |
| Should | Verify install paths on clean macOS arm64/x86_64 and Linux arm64/x86_64 environments | Platform verifiers | 2026-08-20 | Not started | Direct checksum install and Homebrew/source paths start, report identity, and run doctor; unsigned-release Linux installer remains intentionally unshipped |

## Design & UX

| Priority | Item | Owner | Due | Status | Exit evidence / dependency |
|---|---|---|---|---|---|
| Blocker | Confirm all public routes render useful SSR/no-JS content and honest blocked states | Codex | 2026-08-18 | Done for current rendered tree | Production-hash preview rendered `/`, `/start`, `/security`, `/privacy`, `/terms`, `/oauth/callback/`, and a real 404 with meaningful content, correct status behavior, no horizontal overflow, and no console errors; callback query values were absent from raw SSR and no-JS recovery was present |
| Blocker | Complete wide/narrow visual QA and interaction-state QA | Codex | 2026-08-18 | Partially proven | Desktop, effective 355 px narrow, focus, copy success, OAuth ready, clipboard denial, expiry, recovery, and 404 behavior were inspected; no clipping or runtime errors were found. Native 320 px, 200% zoom, complete keyboard traversal, copy-payload readback, and a second browser remain open |
| Blocker | Verify public copy against the exact CLI command tree and current capability semantics | Codex | 2026-08-18 | Done on proven parent; checklist contract pending | Authoritative source contracts validated public `cfctl` examples, version pins, support stop conditions, and plan/apply/verification language on `c3eb4bf…`; the checklist-bearing child must rerun the focused documentation contract and current-object gate |
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
| Blocker | Publish install/auth/catalog/plan troubleshooting guidance | Codex + Support owner | 2026-08-20 | Complete in source candidate; publication pending | The committed operator runbook consolidates install mismatch, no-profile/fallback-store, catalog drift, blocked capability, and uncertain-plan recovery responses; exact-object proof enforces its no-secret, no-bypass, and no-replay language. Hosted merge/publication and named support-owner acceptance remain separate |
| Blocker | Define security escalation and response handoff | Security owner | 2026-08-20 | Partially proven | `SECURITY.md` exists; verify its destination and add named responder/coverage expectations |
| Should | Prepare concise support responses for install mismatch, credential fallback, catalog drift, blocked writes, and rectification | Support owner | 2026-08-21 | Done in proven parent; owner acceptance pending | The launch support triage table supplies copy-ready safe responses and stop conditions while prohibiting credentials, raw-provider bypass, plan edits, and replay |
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
| Blocker | Resolve and authenticate the exact Cloudflare account/site/Worker/domain target | Operator + Codex | 2026-08-20 | Not started | Governed live reads bind account, service, route, DNS, certificate, and current deployment identity |
| Blocker | Produce and review the exact site mutation plan | Codex + Operator | 2026-08-20 | Not started | Plan records operation ID, account/targets, diffs, cost, permissions, verification, compensation, and warnings; no apply yet |
| Blocker | Approve and run only the reviewed operation ID if site launch is selected | Operator | 2026-08-21 | Blocked on decision/plan | `plans approve --yes` then `plans run`; approval does not cover OAuth or release publication |
| Blocker | Perform authenticated post-deployment readback | Codex | 2026-08-21 | Not started | Route, source marker, security/cache headers, critical copy, 404, and OAuth callback policies match the released source |
| Blocker | Verify custom domain, DNS, TLS, and publisher-domain ownership | Codex + Operator | 2026-08-21 | Not started | Governed provider read plus public HTTP/DNS evidence; current environment DNS failure is not evidence that the domain is absent |
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

- [x] Proven parent `c3eb4bf…` / `79134763…` is clean, full-gate green, and independently `REVIEW_GREEN`.
- [ ] The publication record binds the checklist-bearing child as clean and current-object gate/review green, then records its distinct push, hosted review, and merge receipts; local proof cannot close the hosted planes.
- [x] PR #136 is merged and its exact merge commit is identified; its unreviewed code remains inside the final-tree review scope.
- [ ] The final installed candidate's `cfctl catalog coverage --json` passes after fresh sync, including compatibility with the previously failing persisted format.
- [ ] Before publication, attach an uncached `cargo xtask verify` receipt for the exact clean checklist-bearing candidate with no weakened gate or skipped assertion; the parent receipt is historical after this reconciliation.
- [ ] Issue #108 has current real-Linux Secret Service evidence or the release is explicitly held.
- [ ] All public commands/copy, OAuth callback security cases, keyboard/zoom/reduced-motion cases, and dependency/secret scans pass.
- [ ] Privacy, terms, security, license, accessibility, support, and incident ownership are accepted by named owners.
- [ ] Reproducible release artifacts and a tested rollback are available.
- [ ] Every selected protected action has exact authorization, successful execution evidence, and its own readback.
- [ ] No P0/P1 defect remains open; accepted lower-severity deferrals have owner, consequence, and closure date.

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
| 1 | Close the checklist-bearing source object | One checklist-only child of proven `c3eb4bf…` | Clean SHA/tree, focused documentation contract, uncached `cargo xtask verify`, and independent exact-object `REVIEW_GREEN` | Local source/test/review only; no push, install, release, or provider action |
| 2 | Publish and integrate the source candidate | Edge 1 green and explicit hosted-publication authority | Pushed exact SHA, hosted checks/review, merge commit, and `origin/main` readback | Does not authorize installation, release publication, OAuth, or Cloudflare mutation |
| 3 | Adopt the merged CLI | Exact merge object selected and separate installation authority | Installed `cfctl version`/`doctor` identity matches merge; fresh `catalog sync` and real-store `catalog coverage` pass; Pages `catalog show`/`guide` remain available with non-null exact call argv | Does not authorize a Pages call, plan approval, or execution |
| 4 | Close platform and human launch blockers | Installed adoption green | Real Linux Secret Service receipt closes or explicitly holds issue #108; four-platform install checks; native keyboard/320 px/200% zoom/reduced-motion acceptance; named security/privacy/legal/support/incident owners; OAuth and site scope decisions | Human acceptance is recorded, not inferred from source tests |
| 5 | Assemble unsigned release evidence | Exact merged/adopted source and edge 4 disposition | `cargo xtask assemble` produces two-build reproducibility, four target binaries, SPDX SBOMs, provenance, checksums, and installer/formula artifacts; independent inventory review passes | No signing or upload |
| 6 | Build and validate signed release artifacts | Edge 5 green and explicit signing/notarization authority plus identities | `cargo xtask release` binds signatures, notarization, provenance, checksums, and the exact four-platform artifact set | No GitHub publication or announcement |
| 7 | Publish the CLI release | Edge 6 green and explicit release-publication authority | Exact tag/release, immutable uploaded assets, checksum/provenance readback, and clean-environment install verification | Does not publish the website or promote OAuth |
| 8 | Publish `cfctl.com` if selected | Site scope selected; exact account/service/domain reads and reviewed plan exist | Exact plan approval/run receipts, authenticated route/source/header/content/404/callback readback, DNS/TLS/domain verification, and timed rollback rehearsal | Site transaction only; OAuth remains separate |
| 9 | Promote OAuth if selected | OAuth scope selected and security/privacy acceptance complete | Separately reviewed promotion plan, callback/provider configuration readback, redacted log verification, and tested revoke/disable compensation | Does not alter CLI release or site beyond the exact OAuth plan |
| 10 | Go live and observe | All selected blocker edges green; operator records go | Go/no-go decision, announcement identity, monitoring/on-call activation, T+1/T+7 schedule, and content-free health/support receipts | Any failed readback invokes the rollback plan and freezes announcements |

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
| Historical D1-import plans lacked the later `max_source_bytes` field | Codex | 2026-08-16 | DONE IN PROVEN PARENT; adoption open | Clean `c3eb4bf…` reads the isolated real historical store and rejects zero bounds at planning and execution; the exact parent full gate and independent review are green. Hosted merge, installation, and installed PATH readback remain open |
| Sandbox cannot connect to the peer-owned configured `sccache` daemon | Codex + environment owner | 2026-08-16 | Mitigated for proof | Preserved the active peer process and used the shim's gate-preserving cache-free re-entry; `cargo-gate` and all authoritative assertions remained active |
| PR #136 merged without a recorded review decision/checks | Independent reviewer | 2026-08-17 | MERGED; local proof debt discharged | Merge commit `45e967bd…` is the parent of proven `c3eb4bf…`; the combined tree passed the exact-object full gate and independent review. The new checklist-only child still requires its own current-object proof before publication |
| GitHub issue #108: real Linux Secret Service proof | Linux verifier | 2026-08-18 | BLOCKER | Run the isolated security-layer verification on a real host and attach exact evidence |
| Public OAuth is disabled and no current profile is selected | Operator | 2026-08-19 | Decision blocker only if OAuth is launch scope | Choose scoped-token-only launch or authorize a separate permanent OAuth promotion campaign |
| Current live `cfctl.com` state is unverified from this run | Codex + Operator | 2026-08-20 | BLOCKER if site is launch scope | Governed account read plus independent public DNS/HTTP readback; local DNS failure is inconclusive |
| Support, incident, legal/privacy, and accessibility owners are unnamed | Operator | 2026-08-19 | BLOCKER | Assign named people or explicitly retain each role |

## Current evidence snapshot

- **Source:** the immutable proven parent is clean commit
  `c3eb4bf51e588c37ff16ef10ad98795904323b96`, tree
  `79134763c34ecf895265e2bd7baff1d58f184ee1`, on
  `integrate/pages-deployment-governance`, directly above observed
  `origin/main` `45e967bd55049685ab06b0109722354262db6089`. It contains the original
  six-file launch patch plus the exact Pages deployment governance contract.
  This checklist reconciliation is intentionally a separate child so the
  parent receipt remains auditable; the child's exact SHA/tree comes from the
  enclosing clean Git object and its terminal receipt, not self-referential
  prose. The peer-owned canonical checkout remains separately dirty and was not
  normalized.
- **Installed runtime:** `/Users/star/.local/bin/cfctl` reports v1.2.1 at
  `45e967bd55049685ab06b0109722354262db6089`, matching observed
  `origin/main` but not proven parent `c3eb4bf…` or its checklist child.
  `doctor` reports healthy self/PATH identity and zero instruction drift; those
  claims are internal to the installed build and do not establish
  source-candidate alignment.
- **Catalog:** the installed `45e967bd…` binary still lacks the historical
  compatibility repair and its Pages guide remains blocked with five missing
  operation-contract classes and `call_argv=null`. The exact `c3eb4bf…`
  candidate reads an isolated copy of the real 3,440-capability historical
  store, while zero remains non-authorizing, and a fresh official sync exposes
  `pages-deployment-create-deployment` as `dynamic_api` with zero blocking gaps
  and a non-null exact call argv. The downstream plan/run verifier consumes the
  returned deployment ID once, polls only `active`/`idle`, accepts only exact
  project/production terminal `success`, and routes failure, cancellation,
  unknown status, identity drift, provider error, or bounded exhaustion to
  failed verification and rectification without replay. Rollback is a separate
  reviewed operation with declared limits. This is candidate consumer proof,
  not an installed release fix, provider mutation, or live deployment readback.
- **Workspace:** the cloudflare repository is registered and account-pinned.
  The proven parent worktree was clean; this checklist-only child must be
  committed, gated, and independently reviewed as a new object before it can
  inherit publication readiness. Operational observations remain bounded and
  are not launch verification.
- **Authentication:** 19 profiles exist, no current profile is selected, the
  active secret backend is `fallback_file`, and public OAuth is explicitly
  disabled pending a separate promotion transaction.
- **Hosted source (observed 2026-08-15):** v1.2.1 remains the current public
  non-draft, non-prerelease release, published 2026-07-20. PR #136 merged on
  2026-08-15 from head
  `5143bcc0eab1f9743764bf6e932d08c49a97ea00` as merge commit
  `45e967bd55049685ab06b0109722354262db6089`; GitHub records no review
  decision or checks. Issue #108 remains open, unassigned, and without comments
  or real-Linux evidence.
- **Local proof:** the uncached authoritative `cargo xtask verify` run exited 0
  on exact clean parent `c3eb4bf…` and passed formatting, warnings-denied
  Clippy, all workspace tests, 171 catalog tests, 146 Cloudflare request tests,
  OAuth callback tests 5/5, reproducible edge build at
  `4f6d51364c0cb7e93da93c5f8c84a54903b37907c66d3efd91d64a8a7e70f9c1`,
  bridge tests, dependency/license/source policy, a 474-commit secret scan,
  governance/source contracts, and the Linux musl cross-build. The sandbox
  cannot connect to the peer-owned `sccache` daemon, so proof uses the Cargo
  shim's gate-preserving cache-free re-entry; this does not bypass `cargo-gate`
  or any verification assertion. Independent exact-object review of the parent
  returned `REVIEW_GREEN` with no findings at any severity. Both receipts become
  historical for the checklist-bearing child; that child requires a fresh
  current-object gate and review. Local proof is not hosted review, merge,
  publication, installation, deployment, or live readback.
- **Rendered site:** the local preview was bound to the production hashed JS,
  CSS, and Wasm names. All public routes and the 404 rendered without console
  errors or horizontal overflow. OAuth success, malformed/provider-error,
  inert-markup, clipboard-denial, timeout, pagehide/pageshow restoration,
  back-navigation, and no-JS non-rendering paths failed safely. Full native
  keyboard order, 200% zoom, a genuine hidden-tab transition, and live edge
  headers/logging remain unproven. A second native-input attempt established
  the harness boundary: mouse activation focuses the Copy button, Tab does not
  advance through either the high-level or locator key path, browser visibility
  remains hidden after a visible override request, and raw CDP keyboard events
  are explicitly rejected by the backend.
- **Live site:** public DNS/HTTP verification was inconclusive because the
  execution environment could not resolve `cfctl.com`; no deployment or outage
  claim follows from that failure.
