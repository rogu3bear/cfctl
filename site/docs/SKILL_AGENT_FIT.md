# Skill and agent fit audit

Audit date: 2026-08-05. “Loads” means the named `SKILL.md` and its required local references were present and readable. It does not mean every skill is appropriate at every stage.

## Proof summary

- All explicitly named PM skill directories load, frontmatter names match their directories, and their template/example references exist.
- All explicitly named strategy, Leptos, security, SSOT, and deployment skill entrypoints load without broken local references.
- The PM audit wrapper itself is not runnable from the installed cache because the wrapper's required canonical agent/script/command/spec assets are absent. The named PM artifact skills remain independently usable.
- Leptos Design Studio's scanner works against the isolated website worktree. The same scanner is not bounded against the root checkout's `.adopted` directory.

## Routing and fit

| Skill or group | Available agent/tool fit | Proof state | Use/decision |
|---|---|---|---|
| Foundation persona | Default PM reasoning; no special agent required | Loads; proto-persona produced | Used in product mode, low confidence until research. |
| OKR writer → OKR grader | Default PM reasoning | Both load; draft and honest non-grade produced | Sequence makes sense only when grader refuses fabricated outcomes. |
| Build risk → prioritized action plan | Default PM reasoning | Load; review and ranked plan produced | Used as pre-build gate and execution order. |
| User stories → journey → acceptance → edge cases | Default PM reasoning; state-flow agent useful after render | Load; artifacts produced | Correct progressive sequence; journey emotion marked hypothetical. |
| Design sprint readiness | Default PM reasoning | Loads; conditional validation verdict produced | The implemented source and acceptance criteria replace the obsolete design-selection wait; a decider and participants remain necessary for validated user outcomes. |
| Launch checklist → release notes | Release/operator reasoning | Both load; checklist and mainline draft produced | Public website notes remain deferred; shipped `main` changes have bounded draft notes. |
| Market research → market sizing | Web primary-source research; no special local agent required | Load; current primary sources collected; sizing produced | Right-sized market evidence; did not force the generic 50-page report. |
| `improve-website` + `create-website` | Strategy routing | Both load | Existing site makes improve the lead; create contributes rebuild architecture. |
| SSOT | `authority_mapper`, `drift_reconciler`, then scoped `worker` are available | All three stages executed | Proved an existing SSOT and repaired only the stale consumer/install. |
| Leptos Design Studio | Needs Creative Production and Product Design stages; available visual agents can audit when the owner explicitly authorizes substitutes | Scanner and validator pass; required creative plugins unavailable; the owner authorized five bounded substitutes for the implemented direction | Used to produce and inspect the current source; the substitutes did not become the unavailable creative packages or a permanent prose design authority. |
| Leptos opportunity radar | Code/radar reasoning; design-system/spatial agents useful for verification | Loads; post-implementation audit produced | Found delivery closure and callback-state proof—not another framework primitive—as the leading opportunity. |
| Layout spacing repair | `spatial_analyst` is a direct fit | Loads; rendered narrow/wide ownership audit found no proven spacing defect | Applied as a proof lens; no speculative repair or wrapper added. |
| Component consolidation | `design_system_analyst` is a direct fit | Loads; peer audit found actions and copy buttons are intentional semantic variants with shared token geometry | Applied as a proof lens; no universal control component invented. |
| WebGPU/Three.js TSL | Three/WebGPU specialists are available | Loads | Technically possible, strategically unjustified for v1. |
| Define security policy | Security reviewer/tool fit | Loads; exact `site/SECURITY.md` scope was owner-approved and written | Policy now matches implemented callback controls; staging/commit remains a separate authorization gate. |
| Security threat model | Security specialist fit | Loads; owner confirmed exposure/data/deployment assumptions | Grounded `site-threat-model.md` produced with eight abuse paths and stable threat IDs. |
| Deploy + cf-deploy | Governed plan/apply/readback through the CLI | Load; the Workers Assets source contract is present, but account and provider state are intentionally unbound | A `workers.dev` preview is the first live target. Planning waits for a committed release tree, a fresh account/service read, and exact operation approval. |

## Available-agent conclusion

The agent set is strongest for authority mapping, drift reconciliation,
implementation, security review, and post-render design verification. The
grounding, semantics, design-system, spatial, and Leptos-architecture agents
were legitimate bounded substitutes only because the owner explicitly
authorized them; they did not silently become the missing Creative Production
or Product Design packages. The PM auditor wrapper packaging gap also remains a
plugin-owner issue. This separation proves that the named artifact skills work
where their inputs exist without inflating unavailable orchestration into a
pass.
