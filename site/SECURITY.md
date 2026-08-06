# cfctl.com Website Security Policy

This policy composes with the repository-root `SECURITY.md` and governs `site/`.

## System and Scope

The site is an internet-facing cargo-leptos application deployed as a Cloudflare
Worker with static assets. Covered paths include the Leptos routes and
components, Worker request adapter and headers, asset/build scripts, Wrangler
configuration, and `/oauth/callback/`.

The intended v1 has no user accounts, forms, database, object storage,
analytics, third-party scripts, or runtime secrets. Adding any of those changes
this boundary and requires policy and threat-model review.

## Threat Model and Trust Boundaries

All HTTP methods, paths, headers, query parameters, and browser state are
attacker-controlled. The OAuth callback's `state`, `code`, and error fields are
sensitive untrusted inputs crossing from Cloudflare OAuth through the browser
to the waiting local CLI. The website is only a display/copy bridge; the CLI
remains responsible for matching pending state and completing PKCE.

Operator-owned source, deployment configuration, and release artifacts cross a
separate build-and-deploy boundary. Source configuration and local builds do not
prove live edge state.

## Security Invariants

- Primary content must be useful SSR HTML without hydration. The OAuth callback
  may require script, but it must never server-render callback values.
- The callback accepts exactly one bounded state and code, treats all values as
  inert text, removes the query before display, clears sensitive DOM/state on
  expiry or page restoration, and fails closed on malformed, duplicate,
  missing, or oversized input.
- Callback values must not enter logs, analytics, error reporting, external
  requests, referrers, caches, service workers, or build artifacts. Its response
  must be `no-store`, `no-referrer`, and unframeable.
- The callback cannot establish authentication by itself. The CLI must validate
  the pending state, client ID, and PKCE verifier before token exchange.
- CSP must default-deny external execution and connection; framing, objects,
  base-URL changes, and unnecessary browser capabilities remain denied.
- Non-read HTTP methods and unrecognized routes fail with bounded responses that
  expose no stack, environment, credential, account, or evidence data.
- Client bundles and public markup contain no credentials, account IDs, private
  operation bodies, or receipt contents.
- The production artifact is bound to an exact source revision. Deployment uses
  the governed cfctl plan/approval/run lifecycle and closes only after live
  provider and HTTP readback.

## Reportable Findings and Severity Context

Report callback-value disclosure or retention, XSS or script-policy bypass,
cache/referrer/log leakage, request-routing that exposes unintended handlers,
secret or operational-data disclosure, build-to-deploy artifact substitution,
and bypass of the governed deployment boundary.

Remote code execution, credential/token theft, or deploy-authority compromise
is critical. Callback exfiltration, persistent script injection, or
release-artifact substitution is high when realistically reachable. Bounded
denial of service or low-sensitivity metadata exposure is medium or low
according to reproducible impact.

## Out of Scope, Exclusions, and Accepted Risk

Upstream Cloudflare or browser vulnerabilities are reported to their owners.
Findings that require pre-existing full shell control of the operator machine
remain governed by the root policy. Content or cosmetic defects are not security
findings unless they create a deceptive security claim or unsafe operator
action.

No additional accepted risk or finding suppression is authorized by this
policy.

## Known Limitations and Compensating Controls

The callback controls have local unit and browser proof, but they are not live
edge proof. Public OAuth remains unconfigured until `cfctl.com` ownership, site
publication, domain verification, and explicit promotion are complete. Until
then, scoped API-token import remains the supported day-to-day authentication
path.
