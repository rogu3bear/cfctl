# Opportunity index

Scoring is directional: impact and confidence are separated. “Now” means the current website release; “later” requires new evidence.

| Rank | Opportunity | Evidence | Impact | Confidence | Effort | Decision |
|---:|---|---|---|---|---|---|
| 1 | Eliminate unexpected Keychain prompts | Installed binary was commit `39c2228`; current sticky fallback existed only in newer source. Exact `87f8ded` install and D1 read proved the repair. | Very high trust/automation | High | Done | Shipped to `main`; publish build-identity diagnosis. |
| 2 | Turn the landing page into a verified first-read path | Existing site offers one source link and no install/doctor/live-read sequence. | High activation | High | Medium | Build now. |
| 3 | Make plan authority visually legible | Differentiator exists in README/runtime but is prose-heavy. | High comprehension | Medium | Medium | Build now; validate in first-use sessions. |
| 4 | Use Workers Assets as one runtime authority | cargo-leptos coordinates SSR/hydration; Workers supports Rust/Wasm and static assets. Pages Functions uses a different JS file-routing model. | High delivery coherence | High | Medium | Recommend Workers for v1. |
| 5 | Test published commands against the real CLI | CLI surface moves; stale marketing quickstarts are a high-cost failure. | High trust | High | Low | Add release ratchet. |
| 6 | Add privacy-preserving activation evidence | OKRs cannot be graded without a baseline. | Medium learning | High | Medium | Specify after privacy review; no content capture. |
| 7 | Prove full responsive/inclusive coverage | No rendered Leptos surface exists yet. | Medium/high reach | High | Medium | Run after implementation with spatial/state/accessibility review. |
| 8 | Repair PM auditor packaging | Installed PM wrapper expects absent `agents/`, `scripts/`, command, and internal spec assets. | Medium workflow reliability | High | Plugin-owner task | Index defect; do not claim wrapper pass. |
| 9 | Bound design scanner exclusions | Scanner works in the clean worktree but does not ignore root `.adopted`, causing an unbounded scan. | Low/medium workflow speed | High | Low | Report to skill owner; use scoped root meanwhile. |
| 10 | Consolidate components/spacing | No Leptos site components exist yet; premature consolidation would invent drift. | Later maintainability | High | Later | Run radar after render, then repair only proven drift. |
| 11 | Add WebGPU/Three.js visualization | No validated job requires 3D or GPU rendering; it adds bundle/accessibility/maintenance risk. | Unknown | Low | High | Do not build. Revisit only with measured need. |

## Runtime architecture inference

Cloudflare documents Rust Workers through `workers-rs` and supports static assets on Workers. Pages Functions can import Wasm but uses file-based JavaScript function routing; cargo-leptos is designed to coordinate separate server and browser builds. Therefore, keeping the requested cargo-leptos SSR template implies a Workers deployment more directly than a Pages static deployment. This is an inference from the platform contracts, not a Cloudflare statement that Pages cannot host any Leptos site.

Sources: [Rust Workers](https://developers.cloudflare.com/workers/languages/rust/), [Workers Static Assets](https://developers.cloudflare.com/workers/static-assets/), [Pages Functions](https://developers.cloudflare.com/pages/functions/), [Pages routing](https://developers.cloudflare.com/pages/functions/routing/), [Pages module support](https://developers.cloudflare.com/pages/functions/module-support/), [cargo-leptos](https://book.leptos.dev/ssr/21_cargo_leptos.html), [Leptos CSR deployment](https://book.leptos.dev/deployment/csr.html).
