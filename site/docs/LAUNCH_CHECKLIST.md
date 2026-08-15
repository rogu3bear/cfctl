---
artifact: launch-checklist
version: "2.0"
created: 2026-08-15
status: in-progress
launch_candidate: cfctl 1.2.x public-launch closure
source_commit: e584eaee594d9c0ddeb35dce91742e60cec8285c
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
| Current source candidate | Dirty working-tree candidate based on local `main` at `e584eaee594d9c0ddeb35dce91742e60cec8285c`; six launch-scoped files are modified and nothing is staged. Refreshed `origin/main` is `45e967bd55049685ab06b0109722354262db6089`, 17 commits ahead after PR #136 merged. The patch applies cleanly to that remote tree and focused integration tests pass, but the combined tree has not received the authoritative full gate or independent review |
| Current public release | v1.2.1, published 2026-07-20 |
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
| Blocker | Resolve `cfctl catalog coverage --json` failure after a successful catalog sync | Codex | 2026-08-16 | Repair proven; release integration blocked | The installed v1.2.1 binary at current `origin/main` still fails on the historical store. The local repair passes the same store, applies cleanly to current `origin/main`, and passes focused integration tests; final clean integration, full proof, installation, and PATH readback remain open |
| Blocker | Reconcile or close PR #136 without bypassing review/proof | PR #136 owner + Independent reviewer | 2026-08-17 | Merged; final-tree review pending | PR #136 merged to `origin/main` as `45e967bd55049685ab06b0109722354262db6089` on 2026-08-15. GitHub records no review decision or checks, so its code must be covered by the final combined-tree gate and independent review |
| Blocker | Run authoritative source proof on the final candidate | Codex | 2026-08-18 | Needs rerun after integration | The uncached full gate passed on the six-file patch over `e584eaee…`; refreshed `origin/main` is now 17 commits ahead. The patch applies cleanly and focused combined-tree tests pass, but only the eventual clean integrated SHA/tree can close this row |
| Blocker | Prove keyring 4 on a real Linux Secret Service host and close issue #108 | Linux verifier | 2026-08-18 | Blocked | Current open issue #108 requires real-host evidence; macOS fallback-file proof is insufficient |
| Blocker | Obtain independent exact-object review after the final proof run | Independent reviewer | 2026-08-19 | Not started | Review binds the final SHA/tree and all launch-critical diffs |
| Blocker | Keep running, PATH, and source build identities aligned | Codex | 2026-08-19 | Not aligned | `cfctl` on PATH is v1.2.1 at refreshed `origin/main` commit `45e967bd…`, while local `main` remains at `e584eaee…` with the six-file repair. The installed binary therefore contains PR #136 but not the repair and fails real-store catalog coverage; recheck only after clean integration and installation |
| Blocker | Make version/install copy single-sourced and drift-tested | Codex | 2026-08-18 | Done in current tree | Source proof enforces exact workspace-version pins and the current version in `QUICKSTART.md`; `tests::quickstart_release_download_path_fails_closed_on_version_drift` intentionally pins v0.0.0 and proves the gate rejects it with the required current path |
| Should | Assemble the four-platform unsigned release set reproducibly | Codex | 2026-08-20 | Not started | `cargo xtask assemble`; two builds per target, SPDX SBOMs, provenance, checksums, Homebrew formula; no upload |
| Should | Remove or explicitly defer every launch-scoped TODO/known limitation | Codex + Operator | 2026-08-19 | Not started | Decision log names owner, consequence, and closure date for each accepted deferral |

## QA & testing

| Priority | Item | Owner | Due | Status | Exit evidence / dependency |
|---|---|---|---|---|---|
| Blocker | Complete formatting, warnings-denied Clippy, Rust tests, request contract, site proof, bridge proof, security/source contracts, secret scan, dependency policy, and Linux musl cross-build | Codex | 2026-08-18 | Done for working tree | Terminal authoritative gate passed all stages after the repaired test passed six focused runs and the full 301-test library shard |
| Blocker | Add and pass a persistence-compatibility regression for the `max_source_bytes` catalog failure | Codex | 2026-08-16 | Done in working tree | Missing historical bound decodes to zero: readable for coverage and non-authorizing for execution; focused test 1/1 passed |
| Blocker | Exercise OAuth callback missing, duplicate, empty, oversized, error, inert-rendering, clipboard-denial, expiry, background, bfcache, and no-JS states | Codex | 2026-08-18 | Partially proven | Rendered QA proves success/query scrubbing, missing, duplicate, oversized, provider error, inert markup, clipboard denial, two-minute expiry, pagehide, pageshow restoration, back-navigation clearing, and no-JS SSR non-rendering with zero console errors. Empty input remains unit-proven; a genuine hidden-tab transition and live edge-log/config readback remain open |
| Blocker | Complete keyboard, visible-focus, 320 px, 200% zoom, and reduced-motion review | Codex | 2026-08-18 | Partially proven | Rendered QA proves a visible focus ring, effective 355 px narrow reflow with no overflow, and reduced-motion clamping to `0.00001s`; source contracts cover 320 px, forced colors, and status regions. Retesting confirmed click focus reaches the Copy button, but the in-app backend does not advance Tab focus, its visibility override remains hidden, and raw CDP keyboard dispatch is unsupported. Full sequential keyboard order and native 200% zoom therefore remain unverified |
| Blocker | Run dependency and full-history secret scans on the final release tree | Codex | 2026-08-18 | Done for working tree | Advisories, bans, licenses, and sources passed; Gitleaks scanned 458 commits / 9.25 MB with no leaks. Rerun on the eventual committed release tree |
| Should | Run account-backed token lifecycle smoke test in an explicitly disposable account | Operator + Codex | 2026-08-20 | Not started | Separate acknowledgement, reviewed permissions, mint/rotate/revoke/readback receipts; never part of automatic local proof |
| Should | Verify install paths on clean macOS arm64/x86_64 and Linux arm64/x86_64 environments | Platform verifiers | 2026-08-20 | Not started | Direct checksum install and Homebrew/source paths start, report identity, and run doctor; unsigned-release Linux installer remains intentionally unshipped |

## Design & UX

| Priority | Item | Owner | Due | Status | Exit evidence / dependency |
|---|---|---|---|---|---|
| Blocker | Confirm all public routes render useful SSR/no-JS content and honest blocked states | Codex | 2026-08-18 | Done for current rendered tree | Production-hash preview rendered `/`, `/start`, `/security`, `/privacy`, `/terms`, `/oauth/callback/`, and a real 404 with meaningful content, correct status behavior, no horizontal overflow, and no console errors; callback query values were absent from raw SSR and no-JS recovery was present |
| Blocker | Complete wide/narrow visual QA and interaction-state QA | Codex | 2026-08-18 | Partially proven | Desktop, effective 355 px narrow, focus, copy success, OAuth ready, clipboard denial, expiry, recovery, and 404 behavior were inspected; no clipping or runtime errors were found. Native 320 px, 200% zoom, complete keyboard traversal, copy-payload readback, and a second browser remain open |
| Blocker | Verify public copy against the exact CLI command tree and current capability semantics | Codex | 2026-08-18 | Done for working tree | Authoritative source contracts validate public `cfctl` examples against the command tree and plan/apply/verification language; repeat on the eventual committed SHA |
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
| Blocker | Publish install/auth/catalog/plan troubleshooting guidance | Codex + Support owner | 2026-08-20 | Complete in current source; integration pending | The public operator runbook now consolidates install mismatch, no-profile/fallback-store, catalog drift, blocked capability, and uncertain-plan recovery responses; source proof requires its no-secret, no-bypass, and no-replay language. Commit/publication and named support-owner acceptance remain separate |
| Blocker | Define security escalation and response handoff | Security owner | 2026-08-20 | Partially proven | `SECURITY.md` exists; verify its destination and add named responder/coverage expectations |
| Should | Prepare concise support responses for install mismatch, credential fallback, catalog drift, blocked writes, and rectification | Support owner | 2026-08-21 | Done in current source; owner acceptance pending | The launch support triage table supplies copy-ready safe responses and stop conditions while prohibiting credentials, raw-provider bypass, plan edits, and replay |
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

- [ ] Final candidate SHA/tree is clean, pushed, and independently reviewed.
- [x] PR #136 is merged and its exact merge commit is identified; its unreviewed code remains inside the final-tree review scope.
- [ ] The final installed candidate's `cfctl catalog coverage --json` passes after fresh sync, including compatibility with the previously failing persisted format.
- [ ] `cargo xtask verify` passes at the exact clean integrated candidate with no weakened gate or skipped assertion.
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
| Historical D1-import plans lacked the later `max_source_bytes` field | Codex | 2026-08-16 | REPAIR AND FORWARD-APPLICATION PROVEN; release integration open | Installed `45e967bd…` fails the historical store; the local patch succeeds, applies cleanly over that remote tree, and its three behavioral tests plus support/version contracts pass in a disposable combined-tree projection. Finish clean integration, full gate, installation, and PATH readback |
| Sandbox cannot connect to the peer-owned configured `sccache` daemon | Codex + environment owner | 2026-08-16 | Mitigated for proof | Preserved the active peer process and used the shim's gate-preserving cache-free re-entry; `cargo-gate` and all authoritative assertions remained active |
| PR #136 merged without a recorded review decision/checks | Independent reviewer | 2026-08-17 | MERGED; proof debt remains | Merge commit `45e967bd…` is current `origin/main`; include all 17 upstream commits and the six-file repair in the next clean exact-tree gate and independent review |
| GitHub issue #108: real Linux Secret Service proof | Linux verifier | 2026-08-18 | BLOCKER | Run the isolated security-layer verification on a real host and attach exact evidence |
| Public OAuth is disabled and no current profile is selected | Operator | 2026-08-19 | Decision blocker only if OAuth is launch scope | Choose scoped-token-only launch or authorize a separate permanent OAuth promotion campaign |
| Current live `cfctl.com` state is unverified from this run | Codex + Operator | 2026-08-20 | BLOCKER if site is launch scope | Governed account read plus independent public DNS/HTTP readback; local DNS failure is inconclusive |
| Support, incident, legal/privacy, and accessibility owners are unnamed | Operator | 2026-08-19 | BLOCKER | Assign named people or explicitly retain each role |

## Current evidence snapshot

- **Source:** local `main` remains at
  `e584eaee594d9c0ddeb35dce91742e60cec8285c` with six unstaged
  launch-scoped files. Refreshed `origin/main` is
  `45e967bd55049685ab06b0109722354262db6089`, 17 commits ahead after PR
  #136 merged. The exact dirty patch applies cleanly over that remote tree;
  three focused behavioral tests and both support/version source contracts pass
  in a disposable combined-tree projection. This is forward-application proof,
  not a clean candidate, full gate, or review.
- **Installed runtime:** `/Users/star/.local/bin/cfctl` reports v1.2.1 at
  `45e967bd55049685ab06b0109722354262db6089`, matching refreshed
  `origin/main` but not local `main` plus the repair. `doctor` reports healthy
  self/PATH identity and zero instruction drift; those claims are internal to
  the installed build and do not establish source-candidate alignment.
- **Catalog:** the installed `45e967bd…` binary fails against the real stored
  catalog with `missing field max_source_bytes at line 240 column 5`. The local
  working-tree repair makes the absent historical bound decode as zero while
  keeping zero non-authorizing. Both the local patch and its disposable
  projection over current `origin/main` successfully read the same store and
  report 3,440 capabilities. This is focused compatibility proof, not an
  installed release fix.
- **Workspace:** the cloudflare repository is registered and account-pinned;
  the launch candidate is intentionally dirty with the scoped changes.
  Current operational observations are bounded/truncated and are not launch
  verification.
- **Authentication:** 19 profiles exist, no current profile is selected, the
  active secret backend is `fallback_file`, and public OAuth is explicitly
  disabled pending a separate promotion transaction.
- **Hosted source:** v1.2.1 remains the latest public release, published
  2026-07-20. PR #136 merged on 2026-08-15 from head
  `5143bcc0eab1f9743764bf6e932d08c49a97ea00` as merge commit
  `45e967bd55049685ab06b0109722354262db6089`; GitHub records no review
  decision or checks. Issue #108 was refreshed and remains open, unassigned,
  with no comments or real-Linux evidence.
- **Local proof:** an earlier exact-tree `cargo xtask verify` run exited red when
  `pages_git_proof_is_prompt_free_bounded_and_terminates_its_process_group`
  could not read its temporary process-ID file. The test had used a one-second
  timeout while assuming its shell process would start and record both PIDs
  within that same interval. The probe now uses the production local-Git
  configuration bound of five seconds without weakening its timeout or
  descendant-termination assertions. It passed six consecutive focused runs,
  and the contention-scale `cfctl-cli` library shard passed 301/301 in 266.15
  seconds. The subsequent authoritative `cargo xtask verify` run exited 0 and
  passed formatting, warnings-denied Clippy, all workspace and 144 Cloudflare
  request tests, OAuth callback tests 5/5, reproducible edge build at
  `4f6d51364c0cb7e93da93c5f8c84a54903b37907c66d3efd91d64a8a7e70f9c1`,
  bridge tests 3/3, dependency/license/source policy, a 458-commit secret scan,
  governance/source contracts, and the Linux musl cross-build. The sandbox
  cannot connect to the peer-owned `sccache` daemon, so proof uses the Cargo
  shim's gate-preserving cache-free re-entry; this does not bypass `cargo-gate`
  or any verification assertion. Local proof is not commit review, merge,
  publication, deployment, or live readback.
- **Current-tree refresh:** after adding the fail-closed QUICKSTART drift
  regression, launch support triage contract, and refreshed rendered evidence,
  a new uncached authoritative `cargo xtask verify` terminal run exited 0 for
  the exact six-file patch over `e584eaee…`. After `origin/main` advanced to
  `45e967bd…`, a disposable projection proved that the patch applies cleanly
  (two runtime hunks shifted by 151 lines), the historical decode test passes,
  the timeout/process-group test passes at five seconds, zero-bound D1 planning
  and execution remain rejected, and both support/version source-contract tests
  pass. The combined tree has not received the authoritative full gate.
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
