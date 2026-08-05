# HORIZON — cfctl product website

Created: 2026-08-05
Stage: draft

Decision status: owner and required creative-stage decision pending.

This is the sole design authority for the scoped surface. No `NORTH_STAR.md` exists in this repository; product semantics are grounded in the cited README and runtime policy. Existing UI is functional evidence, not a style source.

## 1. Frame

- Surface and routes: `/`, `/start`, `/security`, `/privacy`, `/terms`, and not-found.
- Primary user: the accountable Cloudflare operator who delegates selectively to agents.
- Primary job and success state: understand the governance model, install the intended build, and complete one verified read.
- Design ambition: make careful infrastructure operation feel faster, clearer, and more tangible than direct API improvisation.
- Scope: public product/activation website and its edge runtime.
- Non-goals: product dashboard, authentication UI, D1 lab, contact database, full documentation mirror, WebGPU scene.

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

- `site/index.html` is one dark static landing page with three feature sections and a source link.
- `site/style.css` is the only existing style authority.
- There is no Leptos manifest, component, route, hydration, or server-function surface in this worktree.
- The external `/Users/star/dev/leptos-cf` template proves cargo-leptos SSR/hydration, Router, hashed assets, and Workers Assets delivery.

### Inferred

- Current content establishes positioning but does not carry a visitor through verified activation.
- cargo-leptos SSR plus Workers Assets is the coherent v1 runtime; Pages would imply a different static/CSR architecture.

### Proposed

- Replace the static page with a minimal standalone Leptos crate under `site/`.
- Use useful SSR HTML, modest hydration for copy/status affordances, and no persistence.

### Content and capability inventory

| Item | User value | Source | Required states | Keep, change, or remove |
|---|---|---|---|---|
| Governed control-plane promise | Relevance and differentiation | `README.md:3-15` | Default | Keep semantics, rewrite hierarchy |
| Install and verification path | First success | `QUICKSTART.md`, CLI | Copy success/failure, stale build, unsupported platform | Add |
| Eight-stage lifecycle | Authority comprehension | `README.md:77-86` | Wide, narrow, reduced motion | Add as primary visual story |
| Security/local custody | Trust evaluation | `docs/runtime-policy.md` | Fallback and explicit repair | Expand |
| Privacy and terms | Legal/trust | Existing routes | Direct navigation, no JS | Preserve semantics, redesign |
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

Status: blocked. The required Creative Production plugin/stage is not installed. Available design-review agents are not silently substituted.

- Provisional territory for owner discussion: **Control Ledger** — warm paper/ink contrast, precise orange boundary marks, content-addressed receipt motifs, and visible state transitions.
- No generated artifact or asset is authoritative yet.

## 10. Product Design Options

Status: not generated. The required Product Design plugin/stage is unavailable.

### Direction A — Control Ledger (provisional recommendation)

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

Status: not selected. Owner must choose an exact direction or authorize an explicit substitute process.

## 12. Visualize Full-Design Review

Status: not run. After selection, review all coverage rows as an inspectable preview with wide and narrow captures.

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

- Canonical route-tree change: replace static files with one Leptos Router tree.
- SSR route generation/server mount: Workers request adapter from the template, without D1.
- Feature/bundle boundary: `ssr` and `hydrate`; minimal client islands.
- Navigation/access/capability inventory: public routes only, no authentication or role gate.
- No-JS behavior: all primary content and ordinary links work; copy feedback degrades to selectable text.

## 15. Idea Server

- Dev-only route: `/__ideas/cfctl-site`
- Feature/config gate: development-only `ideas` feature or remove before production.
- Full Design Coverage rows implemented: all routes and shared regions after selection.
- Fixture source and mutation policy: compile-time copy only; no Cloudflare mutation.
- Run command: to be set after crate extraction.
- Readback URL: local loopback only.
- Promotion/removal plan: selected components move to canonical routes; dev route removed before launch.

## 16. Responsive and Inclusive Behavior

- Wide hierarchy: editorial split with lifecycle occupying primary horizontal span.
- Narrow hierarchy: single semantic column; commands scroll locally, never page-wide.
- DOM/reading/focus order: identical to task order in Section 7.
- Keyboard and visible focus: all controls reachable with high-contrast focus ring.
- Reflow, overflow, long content, and zoom: 320px/200% proof; no fixed-height content regions.
- Reduced motion and contrast: state is textual/iconographic; motion optional and disabled by preference.

## 17. Comparison and Proof Plan

- Focused source/architecture ratchets for route inventory, template residue, and CLI commands.
- SSR HTML assertions for every route and critical heading/command.
- SSR and hydrate feature builds via cargo-leptos.
- Release-shaped asset hash and Worker shim verification.
- Browser deep-link, hydration, console/page-error, and copy-state checks.
- Wide/narrow screenshots compared to the selected authority.
- Keyboard, focus, contrast, zoom, reduced motion, and no-JS checks.
- Evidence limits: screenshots do not prove semantics or accessibility APIs by themselves.

## 18. Non-goals and Reversibility

- Non-goals: authenticated product UI, account data, forms, D1, WebGPU, third-party analytics.
- Feature flag or isolation boundary: standalone `site/` Cargo workspace and Workers config.
- Files/components to remove if rejected: new Leptos crate; current privacy/terms content remains recoverable from Git.
- Old shared primitives: none.
- Data or migration impact: none.

## 19. Decision Log

| Date | Decision | Evidence/artifact | Consequence |
|---|---|---|---|
| 2026-08-05 | Preserve product semantics but replace the static visual system | README/runtime policy and current site scan | Existing CSS is not design authority |
| 2026-08-05 | Recommend Workers Assets for cargo-leptos SSR | Platform and Leptos primary docs | Pages is not the canonical v1 target unless owner overrides |
| 2026-08-05 | Reject WebGPU for v1 | No validated job; bundle/accessibility cost | Use semantic HTML/CSS for the lifecycle |
| 2026-08-05 | Stop before visual implementation | Required creative/product-design stages unavailable | Owner decision required |
