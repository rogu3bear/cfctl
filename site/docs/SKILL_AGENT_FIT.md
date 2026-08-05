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
| Design sprint readiness | Default PM reasoning | Loads; conditional verdict produced | Waits on design authority, decider, and participants. |
| Launch checklist → release notes | Release/operator reasoning | Both load; checklist and mainline draft produced | Public website notes remain deferred; shipped `main` changes have bounded draft notes. |
| Market research → market sizing | Web primary-source research; no special local agent required | Load; current primary sources collected; sizing produced | Right-sized market evidence; did not force the generic 50-page report. |
| `improve-website` + `create-website` | Strategy routing | Both load | Existing site makes improve the lead; create contributes rebuild architecture. |
| SSOT | `authority_mapper`, `drift_reconciler`, then scoped `worker` are available | All three stages executed | Proved an existing SSOT and repaired only the stale consumer/install. |
| Leptos Design Studio | Needs Creative Production and Product Design stages; available visual agents can audit but are not silent substitutes | Scanner loads; required creative plugins unavailable | HORIZON drafted; stop for owner decision before implementation. |
| Leptos opportunity radar | Code/radar reasoning; design-system/spatial agents useful for verification | Loads; current scan sees no Leptos app | Run after implementation to find evidence-backed improvements. |
| Layout spacing repair | `spatial_analyst` is a direct fit | Loads; no rendered drift yet | Conditional post-render, not a design generator. |
| Component consolidation | `design_system_analyst` is a direct fit | Loads; no component duplication yet | Conditional after components exist. |
| WebGPU/Three.js TSL | Three/WebGPU specialists are available | Loads | Technically possible, strategically unjustified for v1. |
| Define security policy | Security reviewer/tool fit | Loads; existing policy inspected | Requires exact proposed diff and explicit approval before writing. |
| Security threat model | Security specialist fit | Loads | Requires scope check-in before final model. |
| Deploy + cf-deploy | Governed plan/apply/readback through the CLI | Load; exact install and live read proved | Prepare is authorized; apply waits for exact operation approval. |

## Available-agent conclusion

The agent set is strongest for authority mapping, drift reconciliation, implementation, and post-render design verification. It does not contain a native replacement for the Design Studio's named Creative Production/Product Design stages or the missing PM auditor package assets. Those gaps should remain explicit rather than being masked by a generic agent.
