# Prioritized action plan

## P0 — trust and release boundary

| Action | Status | Evidence/exit condition |
|---|---|---|
| Repair repeated Keychain prompts through existing SSOT | Done | Installed and source SHA `87f8ded` match; `doctor` reports sticky `fallback_file`; authenticated D1 read returned 200 without prompt. |
| Reconcile substantive branches before site work | Done | Pages, quick tunnel, and WebSockets merged; exact merged SHA proved and pushed. |
| Select the HORIZON direction | Blocked on owner | Exact design-stage decision recorded in `HORIZON.md`. |
| Select Workers vs Pages | Recommendation ready | Workers Assets selected for cargo-leptos SSR, or explicit owner override recorded. |
| Build minimum Leptos routes | Pending | SSR/hydration/Router build green; no template residue. |
| Define/review security policy delta | Pending approval | Exact `SECURITY.md` diff shown before any write. |
| Complete threat model | Pending scope answers | Trust boundaries, threats, mitigations, and residual risk accepted. |

## P1 — activation proof

| Action | Status | Evidence/exit condition |
|---|---|---|
| Test every published command | Pending | CI/source ratchet rejects CLI drift. |
| Render and review wide/narrow routes | Pending | Screenshots, keyboard path, reduced motion, no console errors. |
| Specify minimal analytics | Pending | Content-free events, retention, consent, and bot handling approved—or explicit no-analytics launch. |
| Recruit first-use participants | Pending | Mix and protocol recorded; no outcome claims before sessions. |
| Create launch checklist and rollback | Drafted | All required items closed or named blockers. |

## P2 — validated expansion

- Deeper task guides driven by observed search and support demand.
- Interactive local plan explainer only if it improves comprehension.
- Pages static distribution only if a separate CSR use case is proven.
- WebGPU/Three.js only if a measured visualization need outweighs bundle, accessibility, and maintenance cost.

## Explicitly not prioritized

- A D1-backed marketing contact form.
- Generic “AI-powered” claims.
- A second design system or page-local component copies.
- Broad keyring migration as a workaround for installed-binary drift.
