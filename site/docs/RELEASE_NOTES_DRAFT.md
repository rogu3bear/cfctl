# Draft website production notes

Status: source-candidate notes only. Do not publish this text as a deployment,
custom-domain, CLI release, or OAuth claim until the corresponding receipts and
live readbacks exist.

## What the website candidate contains

`cfctl-site` is a server-rendered Leptos application for Cloudflare Workers and
Workers Assets. It explains the ordered read, plan, approval, execution, and
verification boundary; provides a first-read path; and exposes direct security,
privacy, terms, and bounded OAuth callback routes.

The website declares no account system, forms, application database, object
storage, analytics, runtime secrets, or third-party scripts. Ordinary pages are
no-cache, callback responses are no-store and no-referrer, framing is denied,
and the release CSP prevents form submission and cross-origin connections.

## Production proof added in this candidate

The repository now owns a live-site verifier that checks:

- the home, start, security, privacy, terms, callback, and 404 routes;
- security, referrer, framing, permissions, HSTS, content-type, and cache
  headers;
- absence of callback query sentinels from server-rendered HTML;
- the no-store asset manifest; and
- nonempty immutable JS, Wasm, and CSS assets whose filenames bind their
  manifest hashes.

The authoritative local gate tests the verifier's success and failure
contracts. Running that gate proves the verifier and artifact locally; only a
post-deploy verifier run proves a named live origin.

## Deployment boundary

The selected carrier is the `cfctl-site` Worker described by
`site/wrangler.toml`. Production uses two governed operations: upload one inert
Worker version, then promote exactly that reviewed UUID to 100% traffic. The
`workers.dev` deployment must pass provider and runtime readback before a
separate `cfctl.com` domain transaction begins.

Public OAuth remains disabled. Publishing the Worker or `cfctl.com` does not
create, configure, or promote an OAuth client. The event-ingress bridge and a
new downloadable CLI release are also outside this website transaction.

## Operator impact

- Use `cfctl version --json`, `cfctl doctor --json`, and
  `cfctl agents doctor --json` to bind the running control plane before live
  work.
- Use a profile owned by `cfctl-site`; do not reuse an unrelated deployment
  profile solely because it points at the same account.
- Treat upload, promotion, domain attachment, and rollback as distinct
  plan/approve/run/verify lifecycles.
- If execution crosses a provider boundary and becomes uncertain, inspect the
  operation status and use its governed recovery path; never replay it.

## Claims intentionally withheld

Until current receipts exist, these notes do not claim that a Worker version
was uploaded, traffic changed, `workers.dev` passed, `cfctl.com` resolves, TLS
is valid, the website is publicly launched, a CLI release was published, or
OAuth was enabled.
