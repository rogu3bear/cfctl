# Build risk review

Decision: **Validate the implemented small build** against the acceptance
criteria before release.

## Primary risk

Desirability and activation, not technical feasibility. The repository already proves a static site and a working Leptos-on-Workers template. What is unproven is whether the intended operator understands the differentiated governance model quickly enough to install and complete a first read.

## Risk matrix

| Risk | Evidence | Probability | Impact | Treatment |
|---|---|---:|---:|---|
| Governance value reads as abstract compliance prose | Current page has strong claims but little executable path | High | High | Put the plan lifecycle and copyable quickstart above generic feature inventory. |
| Leptos/Workers complexity delays learning | Template build path exists, but a full starter carries D1 and lab residue | Medium | Medium | Extract only Router, SSR/hydration, asset hashing, and Workers Assets runtime. |
| Pages/Workers ambiguity creates two deployment authorities | cargo-leptos SSR maps naturally to Workers; Pages static would change build/runtime model | High | High | Select one canonical Workers deployment for v1; treat Pages as a later static alternative. |
| Analytics harms the local-first trust promise | No instrumentation policy exists | Medium | High | Launch without behavioral analytics or collect only documented, content-free activation events after review. |
| Credential prompt regression damages trust | Old installed binary demonstrated this failure mode | Medium | High | Publish exact build identity and `doctor` verification; retain sticky fallback tests. |
| Visual ambition obscures accessibility or performance | The implemented direction has bounded render evidence, but complete keyboard, native 320 px, 200% zoom, and second-browser acceptance remain open in `LAUNCH_CHECKLIST.md` | Medium | Medium | Review the exact `site/src` and `site/style/main.css` candidate against `ACCEPTANCE_CRITERIA.md`; retain SSR useful content, reduced motion, keyboard proof, narrow-screen proof, and a performance budget. |

## Smallest build that tests the thesis

- Home route with product promise, real quickstart, and lifecycle explanation.
- Start route with install → doctor → catalog → authenticated read.
- Security route linking the actual policy and explaining local credentials.
- Privacy and terms routes.
- No account dashboard, D1 demo, contact database, WebGPU, or generic starter patterns.

## Stop conditions

- The exact site source and `ACCEPTANCE_CRITERIA.md` are not bound for review,
  or the rendered candidate fails a required criterion without an owned repair
  or explicit release disposition.
- Published commands cannot be tested against the exact CLI.
- Worker build cannot produce useful no-JS SSR HTML.
- Security/threat-model review finds an unresolved high-risk issue.
- Deployment target or rollback path remains ambiguous.
