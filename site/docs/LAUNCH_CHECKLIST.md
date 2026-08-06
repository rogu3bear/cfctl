# Launch checklist

Status: locally implemented; deployment and live-edge closure remain open. An
unchecked item is not implied complete.

## Product and content

- [x] HORIZON direction selected and decision logged.
- [x] Primary audience, promise, limits, quickstart, and lifecycle reviewed.
- [x] All commands checked against exact `cfctl` source.
- [ ] Version/install source is owned and drift-tested.
- [ ] Privacy, terms, security, source, and support links are current.
- [x] No template brand, D1 lab, placeholder database ID, or generic starter copy remains.

## Build and UX

- [x] cargo-leptos SSR and hydrate builds pass with locked dependencies.
- [x] Workers shim and immutable asset hashes verify.
- [x] `/`, `/start`, `/security`, `/privacy`, `/terms`, `/oauth/callback/`, and 404 render directly.
- [x] Useful no-JS HTML verified.
- [ ] Wide, narrow, 200% zoom, keyboard, visible focus, and reduced-motion checks pass.
- [x] No page error, hydration mismatch, console error, or horizontal page overflow in the local desktop/narrow browser proof.
- [x] Local artifact sizes, immutable asset caching, SSR no-cache policy, and callback no-store policy reviewed; live timings remain open.

## Security and privacy

- [x] Exact `SECURITY.md` proposal approved, written, and resolved for `site/`.
- [x] Threat-model scope answered and grounded report written.
- [x] CSP, frame, MIME-sniffing, referrer, permissions, and HSTS policy reviewed and locally tested for the final runtime.
- [x] No secrets, account IDs, operation bodies, or evidence contents in client bundles; analytics is absent.
- [ ] OAuth callback query handling passes bounded-input, inert-rendering, clipboard-denial, expiry, bfcache, and no-JS tests.
- [x] OAuth callback responses are locally proven `no-store`, unframeable, and no-referrer; application analytics and third-party resources are absent. Live provider log posture remains a deployment check.
- [ ] Dependency and secret scans pass on the release tree.

## Cloudflare release

- [x] Canonical target selected: Workers Assets.
- [x] Existing project/domain state read live through cfctl: active `cfctl.com`
  zone, account subdomain `sp5qybrsvz`, no `cfctl-site` Worker, and no attached
  `cfctl.com` Worker domain.
- [ ] Exact mutation plan reviewed for account, target, cost, permissions, verification, and compensation.
- [ ] Operator explicitly approves the exact operation ID.
- [ ] Apply completes and produces durable evidence.
- [ ] Authenticated live read confirms route, source marker, headers, and critical content.
- [ ] Custom domain/DNS verification complete if in scope.
- [ ] Rollback command/plan and previous known-good artifact are available.

## Operations and learning

- [ ] Monitoring owner and incident path named.
- [x] Analytics posture is explicitly “none” and documented.
- [ ] First-use protocol and participant recruitment are ready.
- [ ] Release notes reflect only shipped behavior and known limitations.
- [ ] Post-launch review date scheduled.
