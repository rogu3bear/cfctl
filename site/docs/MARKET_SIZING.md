# Market sizing — operator activation units, not invented revenue

Snapshot date: 2026-08-05. Confidence: directional.

## Defensible top-down boundary

Cloudflare reported 332,466 paying customers and 4,298 large customers at December 31, 2025, while describing millions of free and paying customers and internet properties. Fiscal-year 2025 revenue was $2.1679 billion, up 29.8% year over year. These facts show a large and growing operator ecosystem; they do **not** show that every Cloudflare customer needs cfctl or will adopt an independent CLI.

Primary sources:

- [Cloudflare 2025 Form 10-K](https://www.sec.gov/Archives/edgar/data/1477333/000147733326000016/cloud-20251231.htm)
- [Cloudflare FY2025 results](https://cloudflare.net/news/news-details/2026/Cloudflare-Announces-Fourth-Quarter-and-Fiscal-Year-2025-Financial-Results/default.aspx)

## Units

- TAM boundary: Cloudflare-using organizations with at least one operational change or audit workflow. Observable floor: 332,466 paying customer organizations; upper boundary is unknown because “millions” includes heterogeneous free customers and properties.
- SAM: organizations that use CLI/API automation, manage multiple products/accounts/repositories, and require human or agent governance. No public dataset measures this intersection; mark unknown.
- Initial serviceable beachhead: technical founders, platform teams, and security-conscious operators already using Wrangler/cloudflared or delegating infrastructure tasks to agents.
- SOM: active organizations that install a verified build and complete a content-addressed live read, then return for a governed plan. This must be measured from product activation, not derived from Cloudflare revenue.

## Bottom-up scenario frame

Do not publish a forecast yet. Track a transparent scenario after launch:

`qualified visitors × verified-install rate × first-live-read rate × 30-day retained-organization rate`

All four terms currently lack a quality-reviewed baseline. GitHub stars, traffic, copied commands, and raw downloads are discovery signals, not active-organization counts.

## Adoption evidence and constraints

- Cloudflare maintains Wrangler as its official development CLI, so cfctl must complement rather than imitate its build/deploy job: [Wrangler docs](https://developers.cloudflare.com/workers/wrangler/).
- Cloudflare now documents temporary accounts for agent experimentation, evidence that agent-driven onboarding is an active platform concern: [temporary agent deployments](https://developers.cloudflare.com/changelog/post/2026-06-19-temporary-accounts-for-agents/).
- The cfctl repository was at very early public adoption in the 2026-08-05 live GitHub read. Treat current reach as near-zero and prioritize learning over revenue projection.

## Research needed

- Interviews and workflow diary with 12–20 Cloudflare operators.
- Survey or product telemetry establishing use of CLI/API automation and multi-product complexity.
- Competitor/workaround analysis: Wrangler, Terraform/Pulumi, direct API scripts, dashboard, and agent-specific Cloudflare tooling.
- Retention and willingness-to-pay study only after repeated governed use exists.
