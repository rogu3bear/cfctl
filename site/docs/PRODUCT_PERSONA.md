# Product persona — the accountable Cloudflare operator

Mode: product. Research state: proto-persona. Confidence: directional and low.

## Snapshot

The primary user is an infrastructure-minded engineer, technical founder, or platform operator who manages Cloudflare directly and increasingly delegates work to agents. They are comfortable with a terminal but do not want to memorize the entire Cloudflare API, Wrangler, and dashboard surface. They remain accountable for cost, security, production impact, and rollback.

## Job to be done

When I need to inspect or change Cloudflare, help me discover the supported path, review the exact effect, grant narrowly bounded authority, and get durable verification so I can move quickly without surrendering control.

## Behaviors and context

- Works across accounts, zones, repositories, and several Cloudflare products.
- Uses APIs and CLIs when deterministic; accepts governed UI only for real coverage gaps.
- Expects credentials to stay local and secret values to stay out of logs and plans.
- Distinguishes source configuration, preview, apply, and live readback.
- May hand a task to an agent but expects approval to remain operation-specific.

## Pains

- Cloudflare operations are fragmented across APIs, Wrangler, cloudflared, and dashboard-only paths.
- A successful command does not always prove the desired production state.
- Broad credentials and ambiguous account selection create unacceptable risk.
- Tooling that unexpectedly opens Keychain or browser prompts breaks automation and trust.
- Generic landing pages make it difficult to judge whether a tool is safe enough to install.

## Desired outcomes

- Understand the product contract in under a minute.
- Copy an install path that is current, scoped, and verifiable.
- See the plan-to-approval-to-verification lifecycle before installing.
- Reach one safe authenticated read without unexpected prompts.
- Know where the tool stops, what requires approval, and how to recover.

## Trust triggers

- Exact commands derived from the real CLI.
- Explicit risk, cost, permissions, and verification language.
- Open source, local credential custody, and fail-closed ambiguity.
- Visible proof boundaries and no claim that deployment equals verification.

## Evidence and research gaps

Observed evidence comes from repository doctrine, CLI contracts, tests, and the repaired authenticated D1 read. No user interviews, usability sessions, funnel analytics, or willingness-to-pay research were available. Recruit 5–8 Cloudflare operators across solo, platform-team, and agent-heavy workflows before promoting this to a validated persona.
