# Hypothesis journey map — first verified Cloudflare read

Research basis: repository evidence only. Emotion and behavior claims are hypotheses with low confidence.

| Stage | User goal | Likely action | Friction/risk | Desired evidence | Hypothesized emotion | Opportunity |
|---|---|---|---|---|---|---|
| Discover | Decide whether cfctl is relevant | Skim headline, quickstart, source | “All of Cloudflare” can sound overbroad | Clear adapter/blocked-path contract | Skeptical | Lead with governed coverage, not magic. |
| Evaluate | Decide whether it is safe | Read authority lifecycle and security | Abstract policy prose | Concrete operation lifecycle and local custody | Cautious | Show the boundary visually and link policy. |
| Install | Get the intended binary | Copy platform command | Stale release or PATH collision | Version and exact build identity | Alert | Put verification beside installation. |
| Diagnose | Confirm local readiness | Run `cfctl doctor` | Keychain prompt, missing tool, stale catalog | Backend, PATH build, catalog freshness | Anxious → reassured | Explain healthy and fallback states. |
| Authenticate | Bind a scoped account token | Import via stdin | Account ambiguity or secret exposure | Selected profile and credential availability | Guarded | Use one secret-safe account-pinned example. |
| First read | Prove real access | Resolve and call a read capability | Permission/entitlement 403 | Content-addressed live-read receipt | Curious → confident | Use D1 list or another narrow read; explain 403. |
| First change | Review before authority | Create and inspect a plan | Assumes call mutates immediately | Exact operation ID, diff, cost, rollback | Deliberate | Make plan review the hero interaction model. |
| Verify and return | Close and reuse | Inspect status/readback | Confuses apply with convergence | Post-change verification and evidence class | In control | Preserve proof boundaries throughout docs. |

## Moments that matter

- The first command must not surprise the user with a platform prompt.
- The first permission failure must teach scope, not suggest a broad token.
- The first mutation example must stop at plan review until explicit approval.
- The first deployment claim must include authenticated readback.

## Validation plan

Observe participants locating install verification, explaining plan authority, recovering from a scoped 403, and identifying whether a displayed state is preview, apply, or live read.
