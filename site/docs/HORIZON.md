# HORIZON — cfctl product website

Created: 2026-08-05
Stage: implemented

Decision status: owner selected Control Ledger and explicitly authorized the
available design substitutes on 2026-08-05.

This is the sole design authority for the scoped surface. No `NORTH_STAR.md` exists in this repository; product semantics are grounded in the cited README and runtime policy. Existing UI is functional evidence, not a style source.

## 1. Frame

- Surface and routes: `/`, `/start`, `/security`, `/privacy`, `/terms`, `/oauth/callback/`, and not-found.
- Primary user: the accountable Cloudflare operator who delegates selectively to agents.
- Primary job and success state: understand the governance model, install the intended build, and complete one verified read.
- Design ambition: make careful infrastructure operation feel faster, clearer, and more tangible than direct API improvisation.
- Scope: public product/activation website and its edge runtime.
- Non-goals: product dashboard, general authentication UI, D1 lab, contact database, full documentation mirror, WebGPU scene. The existing OAuth callback bridge remains in scope because the CLI pins it as its redirect URI.

## 2. Semantic Product Contract

| Product meaning | Citation | Capability or behavior that must remain true | Design freedom |
|---|---|---|---|
| Changes are reviewable before and provable after | `README.md:3-12` | Writes become exact plans and verification uses live state | Any presentation that keeps plan/apply/read boundaries explicit |
| Local-first catalog control plane | `README.md:63-71` | Reads, authority, boundary, verification, evidence, and credential custody remain distinct | Any hierarchy consistent with those semantics |
| Lifecycle has eight ordered stages | `README.md:77-86` | Orient through close/rectify stays semantically ordered | May compress visually without deleting authority stages |
| Fallback credential authority must not reopen Keychain prompts | `docs/runtime-policy.md:187-201` | Ordinary credential use stays on governed fallback; repair is explicit | Explain with any accessible pattern |
| Publication requires explicit operator action | `README.md:342-349` | Site/domain/deployment are never silently claimed complete | Any launch presentation preserving approval |
| Evidence presence is not completion | `docs/runtime-policy.md:231-235` | Receipts remain local/content-addressed and claims require the right evidence | Any visual metaphor avoiding false green states |

## 3. Excluded North Star Design Directives

No `NORTH_STAR.md#absent` authority exists. No layout, color, typography, component, or navigation direction is inherited from README prose or the current static site.

## 4. Ground Truth and Functional Inventory

### Observed

- The former static `site/index.html`, `site/privacy.html`, `site/terms.html`, and
  `site/style.css` template paths were replaced by a standalone Leptos 0.8
  crate, one router tree, and the selected Control Ledger system.
- The implementation renders all primary content with SSR and hydrates only
  `CommandBlock` and the isolated OAuth callback bridge.
- The cargo-leptos edge build produces a Rust Worker shim plus content-hashed
  JS, WASM, and CSS served through Workers Assets. No D1, KV, R2, account,
  form, analytics, or third-party-script surface was introduced.
- Local route, browser, responsive, callback, and interaction proof passed on
  2026-08-05. That local proof does not bind an account, Worker service,
  preview hostname, custom domain, or current provider state. Those values must
  be re-read and pinned in a separate deployment plan; deployment and
  post-change live readback remain distinct evidence.

### Inferred

- Current content establishes positioning but does not carry a visitor through verified activation.
- cargo-leptos SSR plus Workers Assets is the coherent v1 runtime; Pages would imply a different static/CSR architecture.

### Implemented

- The standalone `site/` crate now owns the route tree, Worker adapter,
  content-hashed asset pipeline, selected visual system, and zero-persistence
  security boundary.
- Useful SSR HTML is present before WASM; hydration is limited to copy/status
  affordances and browser-only callback validation.

### Content and capability inventory

| Item | User value | Source | Required states | Keep, change, or remove |
|---|---|---|---|---|
| Governed control-plane promise | Relevance and differentiation | `README.md:3-15` | Default | Keep semantics, rewrite hierarchy |
| Install and verification path | First success | `QUICKSTART.md`, CLI | Copy success/failure, stale build, unsupported platform | Add |
| Eight-stage lifecycle | Authority comprehension | `README.md:77-86` | Wide, narrow, reduced motion | Add as primary visual story |
| Security/local custody | Trust evaluation | `docs/runtime-policy.md` | Fallback and explicit repair | Expand |
| Privacy and terms | Legal/trust | Existing routes | Direct navigation, no JS | Preserve semantics, redesign |
| OAuth callback bridge | Complete optional PKCE login without a localhost listener | `site/oauth/callback/index.html`, `crates/cfctl-auth/src/lib.rs:27` | Valid/missing/duplicate/oversized query values, denied clipboard, no JS, expiry, back/forward cache | Preserve behavior; harden as an isolated sensitive route |
| Starter field guide, D1 lab, contact form | Template demonstration only | External template | Not applicable | Remove |

### Current-design diagnosis

The current page has strong headline scale but weak task order: no install verification, no lifecycle model, no security path, and only one generic source CTA. The three equal feature columns flatten the product's core authority distinction.

## 5. Preserve and Replace Boundary

- Preserve product semantics: local-first operation, catalog coverage, scoped credentials, exact approval, live verification, explicit blockers.
- Preserve behavior: direct privacy/terms access and external source access.
- Free to replace: all visual hierarchy, layout, navigation presentation, component shape, spacing, color, type, imagery, motion, and responsive form.
- Existing visual elements intentionally retained: Cloudflare-orange association only, subject to accessible contrast.
- Explicit semantic deltas requiring owner approval: none proposed.

## 6. Full Design Coverage

| Route, screen, or region | Primary task | Required content | Key interactions | Critical states | Wide/narrow coverage |
|---|---|---|---|---|---|
| Global header/footer | Orient and navigate | Brand, Start, Security, Source, legal | Links/menu if needed | Focus, narrow wrap | Both |
| `/` | Evaluate and understand | Promise, quickstart preview, lifecycle, trust boundaries | Copy, route links | No JS, copy failure | Both |
| `/start` | Complete first read | Install, version, doctor, auth, resolve/call | Copy steps | Unsupported OS, 403 explanation | Both |
| `/security` | Evaluate custody/authority | Credential, approval, evidence, reporting | Policy links | Fallback/repair distinction | Both |
| `/privacy` | Understand data handling | Current policy content | Links | No JS | Both |
| `/terms` | Understand terms | Current terms content | Links | No JS | Both |
| `/oauth/callback/` | Return one PKCE authorization response to the waiting CLI | State/code or bounded error; paste instructions | Copy then clear | Missing/mismatched-looking/duplicate/oversized input, denied clipboard, no JS, expiry | Both |
| 404 | Recover | Clear miss and route links | Navigate | Direct deep link | Both |

## 7. Hierarchy Contract

| Rank | Element or user question | Target region | Task/DOM order | Visual weight | Wide behavior | Narrow/state behavior | Rationale |
|---:|---|---|---:|---|---|---|---|
| 1 | What is cfctl and why trust it? | Main hero | 1 | Primary | Promise beside executable proof | Stack promise before command | Evaluation precedes feature detail |
| 2 | Will it mutate now? | Lifecycle | 2 | Primary | Horizontal/ledger sequence | Ordered vertical sequence | Core differentiated job |
| 3 | Can I reach first success? | Quickstart | 3 | Strong | Steps and verified outcome | One step per block | Activation outcome |
| 4 | Where are the boundaries? | Trust section | 4 | Medium | Credential/authority/evidence columns | Sequential disclosures | Security confidence |
| 5 | What next? | Final action | 5 | Strong | Install and source actions | Full-width actions | Clear continuation |

DOM, reading, and focus order remain identical; CSS must not visually reorder meaning.

## 8. Creative Direction Contract

- Target perception and emotional register: deliberate momentum, technical confidence, calm accountability.
- Product-native nouns and verbs: resolve, read, plan, approve, run, verify, rectify, evidence.
- Desired contrast, rhythm, material, imagery, and motion: strong editorial hierarchy, receipt/ledger material, restrained orange signal, precise rule lines, motion only to clarify lifecycle progression.
- Range Creative Production may explore: operational ledgers, boundary maps, evidence stamps, edge/network abstractions without literal cloud stock art.
- Explicit avoid list: neon cyberpunk, generic AI gradients, glass-card wallpaper, dashboard chrome, fake terminal noise, mascots, 3D globe/WebGPU spectacle.
- Accessibility constraints: WCAG AA text/controls, no color-only state, reduced motion, useful no-JS SSR, 320px and 200% reflow.

## 9. Creative Production Territory

Status: owner-selected through an explicitly authorized substitute process. The
required Creative Production plugin/stage was unavailable; the owner authorized
grounding, semantic, design-system, spatial, and Leptos-architecture reviewers
as substitutes rather than treating their output as an implicit replacement.

- Selected territory: **Control Ledger** — warm paper/ink contrast, precise
  orange boundary marks, content-addressed receipt motifs, and visible state
  transitions.
- Substitute review evidence: the 2026-08-05 Grounding Scout, Semantics
  Guardian, Design System, Spatial Hierarchy, and Leptos Architecture returns,
  synthesized into Sections 7–17 of this HORIZON.
- Preserve: ordered authority, evidence-class distinctions, selectable exact
  commands, and calm accountability.
- Avoid: dashboard chrome, generic cards, terminal theater, remote fonts/icons,
  and motion that resembles a real execution.

## 10. Product Design Options

Status: three structural directions compared in text under the explicitly
authorized substitute process. Direction A is owner-selected.

### Direction A — Control Ledger (selected)

- Exact substitute Product Design artifact:
  `/Users/star/.codex/visualizations/2026/08/05/019fd392-3386-79f2-b79a-1d377fc86ff4/control-ledger-review.html`
- Hierarchy thesis: executable proof and the authority ledger share the first viewport.
- Layout grammar: editorial split hero, ruled lifecycle ledger, compact verification receipts.
- Interaction model: copyable commands and progressive state explanation; no simulated product dashboard.
- Wide-to-narrow transformation: split regions become one ordered ledger.
- Tradeoff: distinctive and trustworthy, but needs disciplined type and spacing to avoid feeling bureaucratic.

### Direction B — Edge Observatory (provisional)

- Hierarchy thesis: map intent crossing one controlled boundary to verified state.
- Layout grammar: dark field, topology lines, bounded nodes, focused orange illumination.
- Interaction model: lifecycle emphasis through restrained spatial transitions.
- Wide-to-narrow transformation: topology becomes a vertical causal chain.
- Tradeoff: visually dramatic, with higher generic-cloud and motion risk.

### Direction C — Operator Manual (provisional)

- Hierarchy thesis: quickest path from promise to install to exact commands.
- Layout grammar: bright documentation-first typography, numbered procedures, strong marginal notes.
- Interaction model: minimal hydration and maximum scan/copy efficiency.
- Wide-to-narrow transformation: already linear and robust.
- Tradeoff: clearest and fastest, but less ownable as a brand expression.

These text territories are not substitutes for the missing exact Product Design results.

## 11. Selected Direction

Status: selected by the owner on 2026-08-05.

- Exact selected Product Design result:
  `/Users/star/.codex/visualizations/2026/08/05/019fd392-3386-79f2-b79a-1d377fc86ff4/control-ledger-review.html`
  for **Direction A — Control Ledger**, as specified by Sections 7–10.
- Coverage targets: every row in Section 6 uses the same warm editorial ledger
  system; the OAuth callback uses a deliberately isolated, query-blind shell.
- Selected creative territory: warm paper, near-black ink, mineral-gray rules,
  restrained Cloudflare orange at authority boundaries, and cool blue-gray for
  read/evidence metadata.
- Why it wins: it makes the product's actual differentiator—where authority
  crosses and what evidence proves—more legible than a feature grid or cloud
  topology metaphor.
- Why alternatives lose: Edge Observatory risks generic cloud spectacle and
  motion ambiguity; Operator Manual is clear but does not make the governed
  lifecycle ownable.
- User feedback incorporated: use available design substitutes, select Control
  Ledger, and use Workers Assets. Canonical-domain authority remains a later
  source change gated by live domain and OAuth readback.
- Known risks: ledger motifs can feel bureaucratic; orange can become generic
  brand wash; illustrative states can be mistaken for live execution. Counter
  with generous rhythm, orange only at named boundaries, and explicit evidence
  labels.

## 12. Visualize Full-Design Review

Status: specified for an inspectable, route-switching full-page preview.

- Review form: interactive full-page mockup with route/state switching.
- Visualization path: thread-owned `control-ledger-review.html`; it is review
  evidence only and never production source.
- Coverage: home, start, security, privacy/terms treatment, OAuth callback
  isolation, not-found recovery, wide-to-narrow movement, copy failure, and
  invalid/expired callback states.
- Decisions: lifecycle is the dominant spatial object; commands remain
  selectable SSR content; trust regions are ruled notes rather than cards;
  callback values never appear in the review fixture.
- Limits: no runtime, browser, accessibility, or Leptos proof is implied.

## 13. Shared Design System

| Need | Existing implementation inventory | Keep semantic/behavioral core | Replace visual layer | New shared primitive/token | Migration reason |
|---|---|---|---|---|---|
| Page shell/navigation | Static HTML only | Route access | Yes | `SiteShell`, spacing/container tokens | One route-wide authority |
| Commands | Static `pre` | Selectable command | Yes | `CommandBlock`, copy state | Shared resilient behavior |
| Lifecycle | README list only | Ordered authority semantics | New | `LifecycleLedger`, state tokens | Core product story |
| Evidence | Prose only | Evidence-class distinction | New | `EvidenceReceipt` | Prevent false completion |
| Actions | Plain anchor | Accessible link semantics | Yes | `ActionLink` variants | Consistent focus/contrast |

## 14. Leptos Delivery Map

| Surface/region | SSR content | Island interaction | Shared component/token | Data source | Loading/empty/error/disabled states |
|---|---|---|---|---|---|
| Shell/routes | Full headings, nav, footer | Optional narrow nav | `SiteShell` | Compile-time content | No loading; 404 |
| Command blocks | Full command text | Copy feedback | `CommandBlock` | Compile-time exact commands | Copy unavailable/denied |
| Lifecycle | Full ordered list | Optional focus/highlight | `LifecycleLedger` | README semantics | Reduced motion/no JS |
| Trust receipts | Full evidence text | None | `EvidenceReceipt` | Compile-time content | Not applicable |
| OAuth callback | Shell and privacy instructions only; never server-render query values | Parse, validate, display, copy, clear | `OAuthCallback` isolated route | URL query from Cloudflare OAuth | Missing/invalid/duplicate/oversized, denied clipboard, expired display, no JS |

- Canonical route-tree change: replace static files with one Leptos Router tree.
- SSR route generation/server mount: Workers request adapter from the template, without D1.
- Feature/bundle boundary: `ssr` and `hydrate`; minimal client islands.
- Navigation/access/capability inventory: public routes only, no authentication or role gate.
- No-JS behavior: all primary content and ordinary links work; ordinary copy feedback degrades to selectable text. The OAuth bridge explains that script is required and does not server-render callback values.

## 15. Idea Server

- Dev-only route considered during selection: `/__ideas/cfctl-site`.
- Promotion decision: the selected result was implemented directly in canonical
  routes, so no idea-server route or feature ships in production.
- Local review surface: `cargo build --no-default-features --features
  ssr,local-preview` and `target/debug/cfctl-site` on loopback.
- Fixture and mutation policy: compile-time public copy only; no Cloudflare
  mutation and no sensitive callback fixture in SSR.
- Full Design Coverage rows implemented: all routes and shared regions in
  Section 6, including isolated callback and not-found recovery.

## 16. Responsive and Inclusive Behavior

- Wide hierarchy: editorial split with lifecycle occupying primary horizontal span.
- Narrow hierarchy: single semantic column; commands scroll locally, never page-wide.
- DOM/reading/focus order: identical to task order in Section 7.
- Keyboard and visible focus: all controls reachable with high-contrast focus ring.
- Reflow, overflow, long content, and zoom: 320px/200% proof; no fixed-height content regions.
- Reduced motion and contrast: state is textual/iconographic; motion optional and disabled by preference.

## 17. Comparison and Proof Plan

- Source/architecture ratchets pass for route inventory, callback bounds,
  template residue, zero storage, and immutable asset references.
- SSR route proof returns 200 for every intended route and 404 for an unknown
  path; ordinary route content is meaningful before hydration.
- SSR, hydrate, Worker-WASM, and local-preview builds pass against the installed
  Leptos 0.8 lockfile.
- Browser proof shows the `CommandBlock` island changes its status to `Copied.`;
  the OAuth callback removes its query, displays only validated inert text,
  clears after copy, and rejects duplicate state values.
- The implemented Leptos routes were compared with the selected Product Design
  Control Ledger artifact: editorial split, ruled lifecycle, receipt language,
  warm paper/ink tokens, and narrow ordered movement are present without a
  production Idea Server.
- Wide and 320-class narrow review preserve DOM order and avoid page-wide
  horizontal overflow; semantic landmarks, headings, navigation, buttons, and
  status regions remain present. Keyboard/focus rules, reduced-motion, forced
  colors, and 200% reflow contracts are source-verified, with live assistive
  technology validation still a launch follow-up.
- Evidence limits: local browser and source proof do not prove live Cloudflare
  headers, asset identity, domain binding, real-user comprehension, or outcome
  lift. Those require exact deployment and live readback.

## 18. Non-goals and Reversibility

- Non-goals: authenticated product UI beyond the callback bridge, account data, forms, D1, WebGPU, third-party analytics.
- Feature flag or isolation boundary: standalone `site/` Cargo workspace and Workers config.
- Files/components to remove if rejected: the standalone Leptos crate; the
  superseded static privacy/terms files remain recoverable from Git history.
- Old shared primitives: none.
- Data or migration impact: none.

## 19. Decision Log

| Date | Decision | Evidence/artifact | Consequence |
|---|---|---|---|
| 2026-08-05 | Preserve product semantics but replace the static visual system | README/runtime policy and current site scan | Existing CSS is not design authority |
| 2026-08-05 | Recommend Workers Assets for cargo-leptos SSR | Platform and Leptos primary docs | Pages is not the canonical v1 target unless owner overrides |
| 2026-08-05 | Reject WebGPU for v1 | No validated job; bundle/accessibility cost | Use semantic HTML/CSS for the lifecycle |
| 2026-08-05 | Stop before visual implementation | Required creative/product-design stages unavailable | Owner decision required |
| 2026-08-05 | Select Control Ledger through explicitly authorized substitutes | Owner response plus five bounded substitute reviews | Lock lifecycle-led editorial design and proceed to Leptos implementation |
| 2026-08-05 | Use Workers Assets without embedding a production route | The site needs SSR plus immutable assets, while provider and domain state can drift independently of source | Publish to the exact account-bound preview selected by a later governed plan; review custom-domain attachment separately after preview readback |
| 2026-08-05 | Implement the selected result in canonical Leptos routes | Green edge build plus local route, hydration, callback, and responsive browser proof | Remove superseded static paths; keep deployment/live proof open |
