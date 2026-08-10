# Opportunity index

Scoring is directional: impact and confidence are separated. “Now” means the current website release; “later” requires new evidence.

| Rank | Opportunity | Evidence | Impact | Confidence | Effort | Decision |
|---:|---|---|---|---|---|---|
| 1 | Eliminate unexpected Keychain prompts | Installed binary was commit `39c2228`; current sticky fallback existed only in newer source. Exact `87f8ded` install and D1 read proved the repair. | Very high trust/automation | High | Done | Shipped to `main`; publish build-identity diagnosis. |
| 2 | Close exact `workers.dev` delivery and live readback | The first-read route, Worker SSR, and immutable assets pass locally; governed reads bound the account and proved `cfctl-site` does not yet exist, but no provider apply/live receipt exists. | High activation and truthfulness | High | Medium | Lead next; create the exact plan from the committed release tree, then obtain approval for its operation ID. |
| 3 | Complete sensitive callback lifecycle proof | Success, copy-clear, query sanitation, and duplicate rejection pass; clipboard denial, expiry, bfcache, and cross-browser behavior remain. | High OAuth trust | Medium | Low | Finish before public OAuth promotion. |
| 4 | Validate Control Ledger comprehension | The lifecycle is now visually legible, but persona and journey remain research hypotheses. | High comprehension | Medium | Low | Run five moderated first-use sessions after preview deploy. |
| 5 | Test published commands against the real CLI | CLI surface moves; stale marketing quickstarts are a high-cost failure. | High trust | High | Low | Local commands are source-aligned; add release ratchet before custom-domain promotion. |
| 6 | Add privacy-preserving activation evidence | OKRs cannot be graded without a baseline. | Medium learning | High | Medium | Specify after privacy review; no content capture. |
| 7 | Complete inclusive launch proof | Semantic DOM and narrow reflow pass locally; keyboard capture, 200% text, assistive technology, and cross-browser callback states remain. | Medium/high reach | High | Low/medium | Run on exact preview artifact. |
| 8 | Repair PM auditor packaging | Installed PM wrapper expects absent `agents/`, `scripts/`, command, and internal spec assets. | Medium workflow reliability | High | Plugin-owner task | Index defect; do not claim wrapper pass. |
| 9 | Bound design scanner exclusions | Scanner works in the clean worktree but does not ignore root `.adopted`, causing an unbounded scan. | Low/medium workflow speed | High | Low | Report to skill owner; use scoped root meanwhile. |
| 10 | Re-audit components/spacing after content growth | Current post-render peer/ownership audit finds no accidental geometry or spacing fork. | Later maintainability | High | Later | No change now; rerun when a real peer family drifts. |
| 11 | Add WebGPU/Three.js visualization | No validated job requires 3D or GPU rendering; it adds bundle/accessibility/maintenance risk. | Unknown | Low | High | Do not build. Revisit only with measured need. |

## Runtime architecture inference

Cloudflare documents Rust Workers through `workers-rs` and supports static assets on Workers. Pages Functions can import Wasm but uses file-based JavaScript function routing; cargo-leptos is designed to coordinate separate server and browser builds. Therefore, keeping the requested cargo-leptos SSR template implies a Workers deployment more directly than a Pages static deployment. This is an inference from the platform contracts, not a Cloudflare statement that Pages cannot host any Leptos site.

Sources: [Rust Workers](https://developers.cloudflare.com/workers/languages/rust/), [Workers Static Assets](https://developers.cloudflare.com/workers/static-assets/), [Pages Functions](https://developers.cloudflare.com/pages/functions/), [Pages routing](https://developers.cloudflare.com/pages/functions/routing/), [Pages module support](https://developers.cloudflare.com/pages/functions/module-support/), [cargo-leptos](https://book.leptos.dev/ssr/21_cargo_leptos.html), [Leptos CSR deployment](https://book.leptos.dev/deployment/csr.html).
