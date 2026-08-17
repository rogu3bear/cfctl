# Prioritized action plan

## P0 — trust and release boundary

| Action | Status | Evidence/exit condition |
|---|---|---|
| Repair repeated Keychain prompts through existing SSOT | Done | Installed and source SHA `87f8ded` match; `doctor` reports sticky `fallback_file`; authenticated D1 read returned 200 without prompt. |
| Reconcile substantive branches before site work | Done | Pages, quick tunnel, and WebSockets merged; exact merged SHA proved and pushed. |
| Select Workers vs Pages | Recommendation ready | Workers Assets selected for cargo-leptos SSR, or explicit owner override recorded. |
| Build minimum Leptos routes | Done in source | The current `site/src` route tree, SSR/hydration path, and Worker asset build replace the former template; rendered acceptance and deployment remain separate rows. |
| Review the implemented site at wide and narrow viewports | Pending proof | Current `site/src` and `site/style/main.css` are reviewed against `ACCEPTANCE_CRITERIA.md`; findings are repaired or recorded without treating implementation as its own proof. |
| Define/review security policy delta | Implemented; acceptance open | `../SECURITY.md` governs the current site boundary; named security/privacy acceptance and live configuration readback remain open in `LAUNCH_CHECKLIST.md`. |
| Complete threat model | Implemented; acceptance open | `../site-threat-model.md` records the current scope, trust boundaries, threats, mitigations, and residual risks; a boundary change or named acceptance can require a successor review. |

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
