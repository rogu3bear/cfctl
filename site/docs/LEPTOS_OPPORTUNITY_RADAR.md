# Leptos Opportunity Radar

Audit date: 2026-08-05. This audit describes the implemented local tree; it
does not treat a build as deployment or user-outcome evidence.

## Outcome and current Leptos topology

The desired outcome is one trustworthy first read: an operator should
understand cfctl's authority boundary, identify the intended build, and reach a
non-mutating governed read without mistaking a plan or receipt for live proof.

**OBSERVED:** `site/Cargo.lock` resolves Leptos 0.8.20, leptos_router 0.8.15,
and leptos_meta 0.8.6. The standalone crate separates `ssr`, `hydrate`, and
native-only `local-preview` features. The Worker/Axum server mounts one router
with six named routes plus wildcard fallback; public content is SSR-first.
Only `CommandBlock` and `OAuthCallbackBridge` are islands. There are no server
functions, resources, actions, forms, storage clients, or client data fetches
(`site/Cargo.toml`, `site/src/app.rs`, `site/src/lib.rs`).

**OBSERVED:** the release-shaped client artifact is approximately 199 KB WASM,
16 KB JS, and 8 KB CSS before transfer compression. The Worker build verifies
content-hashed references and a Workers Assets allowlist. Local browser proof
shows successful command hydration and callback state transitions. Production
latency, transfer size, edge CPU, and real-user activation are UNKNOWN.

## Important discoveries and blind spots

1. **OBSERVED — important discovery:** the narrow-islands architecture already
   captures the major Leptos leverage. Replacing it with whole-page hydration,
   server functions, resources, or a CSR rewrite would enlarge the trust and
   bundle boundary without serving the stated outcome. Falsifier: a measured
   journey that requires shared client state or a real server-side data flow.
2. **OBSERVED — important discovery:** delivery closure, not a missing Leptos
   primitive, is now the critical path. The route tree, Worker shim, asset
   hashes, and browser behavior are locally aligned, but no `workers.dev` apply
   receipt or live HTTP readback exists. Falsifier: an exact live deployment
   receipt and matching asset/header probes.
3. **UNKNOWN — blind spot:** first-use comprehension is not measured. The
   Control Ledger may clarify plan/admit/run/verify, or it may feel too
   procedural. The discriminating check is five moderated first-use sessions
   using one non-mutating task, with no analytics added.
4. **UNKNOWN — blind spot:** real edge CPU, cold-start behavior, and transferred
   bytes are unmeasured. Local artifact sizes are not performance evidence. The
   discriminating check is a `workers.dev` preview plus Cloudflare and browser
   timing readback that records no sensitive query content.
5. **OBSERVED — recovery gap:** successful and malformed callback states have
   browser proof; clipboard denial, two-minute expiry, bfcache restoration, and
   cross-browser lifecycle behavior remain launch-proof gaps, not confirmed
   defects (`site/src/routes/oauth_callback.rs`).

## Leptos opportunity map

| Route/callsite | Current pattern | Observed consequence | Outcome | Leptos leverage | Version/prerequisite | Smallest test | Risk |
|---|---|---|---|---|---|---|---|
| All routes / Worker mount | SSR `Routes` with fixed fallback | Meaningful initial HTML and direct deep links work locally | Trustworthy low-JS activation | Preserve SSR and route closure; no new primitive | Leptos 0.8.20; Workers Assets publish | Deploy exact bundle to `workers.dev`, probe every route and asset hash | Account/deploy binding |
| `CommandBlock` | Narrow island around native button/status | Copy works without hydrating surrounding content | Fast, legible command use | Keep island boundary; selectable SSR code is the fallback | `leptos/islands` in both targets | Clipboard success and denial across home/start | Clipboard API variance |
| `/oauth/callback` | Isolated browser-only validation island | Query is erased, success clears, duplicates fail closed | Safe handoff to waiting CLI | Keep local signals/effect; no server function or resource | CLI must enforce state and PKCE | Expiry, pagehide/pageshow, denied clipboard in Safari/Chromium | Sensitive transient value |
| Static route metadata | One global title/description | Route-specific search/share representation is UNKNOWN | Discoverability of Start/Security guidance | SSR route-local metadata is possible | Evidence of search need and canonical URL policy | Inspect search queries/interviews before adding metadata | Low; unproven value |
| Shared shell/ledger/receipts | Semantic SSR components plus central CSS tokens | No observed component or spacing fork in reviewed routes | Coherent authority language | Existing components/tokens are sufficient | Continue source and render drift checks | Re-run after first content expansion | Premature abstraction |

## Alternatives

- **Framework branch — connect live delivery:** keep the current Leptos SSR and
  islands topology, publish its exact content-hashed Worker bundle to
  `workers.dev`, and bind live route/header evidence back to the release.
- **Plain-web simplification branch:** retain semantic anchors, SSR code text,
  and CSS responsive layout; do not introduce router-aware navigation,
  resources, actions, or reactive layout state until a concrete journey needs
  them.
- **New capability branch:** add route-specific SSR metadata and a compact
  install/source provenance receipt only after search or first-use evidence
  shows discoverability confusion.
- **No-change branch:** freeze framework topology after live deployment and
  spend the next learning cycle on operator comprehension rather than code.

## Opportunity vector

| Candidate | User impact | Evidence confidence | Strategic leverage | Urgency | Effort | Risk | Reversibility |
|---|---|---|---|---|---|---|---|
| Exact `workers.dev` deployment and readback | High — unlocks real use and OAuth-origin proof | High — local closure exists, live closure does not | High — converts every local claim into inspectable edge evidence | High | Medium | Medium — provider mutation and domain authority | High with exact plan/rollback |
| Callback lifecycle completion | High for OAuth users; population unknown | Medium — code exists, four states unproven | Medium | High before OAuth promotion | Low | Medium because values are sensitive | High |
| Route-specific metadata | Medium if search discovery matters | Low — no demand evidence | Medium | Low | Low | Low | High |
| Add server functions/resources/actions | Unknown | Low — no data flow exists | Low | Low | Medium | High relative to value | Medium |

Decision rule: prefer the high-evidence delivery branch, then close sensitive
callback states; do not add framework surface to compensate for missing runtime
or user evidence.

## Leading experiment

- **Product belief:** a fast, same-origin SSR site that makes authority stages
  visible will help an operator reach one verified read with less ambiguity.
- **Framework assumption:** the existing Worker SSR plus two islands is enough;
  no client application shell or server-function layer is needed.
- **Smallest representative slice:** publish the exact current bundle to a
  `workers.dev` preview, then exercise `/`, `/start`, `/security`, legal routes,
  404, hashed assets, command hydration, and callback negative states.
- **Before/after evidence:** current local hashes and route/browser receipts
  versus live response headers, asset hashes, transferred bytes, console state,
  and task completion in five moderated first-use sessions.
- **Success:** every live route/status/header/hash matches the contract; no
  unexpected origin requests occur; at least four of five representative
  operators identify the plan-before-run boundary and complete one read without
  assistance.
- **Failure:** route or asset drift, callback leakage, external requests,
  material cold-start failure, or three or more participants confuse plan with
  execution.
- **Stop/rollback:** do not bind `cfctl.com` after a failed preview; compensate
  or roll back the exact Worker version. Stop user testing immediately on any
  callback disclosure.

## Proof matrix

| Proof area | Current evidence | Remaining evidence |
|---|---|---|
| Version/build | Lockfile and separate feature targets; edge build green | Exact committed SHA and clean release provenance |
| Initial HTML | Direct local SSR route/status checks | Live Workers response checks |
| Hydration | Copy island reaches `Copied.` without mismatch warning | Clipboard denial and cross-browser run |
| Route closure | Named routes and 404 mounted locally | `workers.dev` and custom-domain readback |
| Data/security | No forms/storage/analytics/third-party scripts; callback bounds/unit tests | Live CSP/cache/referrer headers and CLI state/PKCE integration |
| Dynamic states | Callback success, copy-clear, duplicate failure | Expiry, pagehide/pageshow, bfcache, denied clipboard |
| Interaction/accessibility | Semantic browser snapshot; narrow overflow check | Keyboard traversal, focus capture, 200% text and assistive-technology run |
| Performance | Artifact byte sizes only | Edge CPU/cold start/transfer timing |
| Outcome | Persona, journey, and OKRs are hypotheses | Moderated first-use baseline |

## Non-opportunities

- Whole-page hydration, CSR migration, server functions, resources, actions,
  D1/KV/R2, and generic authentication UI: no supporting data or mutation job.
- Nested route layouts: the small static route set already shares one shell;
  introducing nesting would not change an observed outcome.
- WebGPU/Three.js: no validated job, while it increases bundle, motion,
  accessibility, and maintenance cost.
- A universal layout/control component system: current semantic components and
  CSS tokens show no proven fork; consolidation now would be speculative.

## Next evidence action

Commit the approved release tree, create an exact deployment plan for
`cfctl-site.sp5qybrsvz.workers.dev`, and review its operation ID. The pinned
profile and account mapping are now proven; further Leptos refactoring has a
worse learning-to-cost ratio than closing the provider evidence boundary.
