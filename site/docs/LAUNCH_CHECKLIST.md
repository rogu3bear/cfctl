# Launch checklist

Status: pre-build draft. An unchecked item is not implied complete.

## Product and content

- [ ] HORIZON direction selected and decision logged.
- [ ] Primary audience, promise, limits, quickstart, and lifecycle reviewed.
- [ ] All commands checked against exact `cfctl` source.
- [ ] Version/install source is owned and drift-tested.
- [ ] Privacy, terms, security, source, and support links are current.
- [ ] No template brand, D1 lab, placeholder database ID, or generic starter copy remains.

## Build and UX

- [ ] cargo-leptos SSR and hydrate builds pass with locked dependencies.
- [ ] Workers shim and immutable asset hashes verify.
- [ ] `/`, `/start`, `/security`, `/privacy`, `/terms`, and 404 render directly.
- [ ] Useful no-JS HTML verified.
- [ ] Wide, narrow, 200% zoom, keyboard, visible focus, and reduced-motion checks pass.
- [ ] No page error, hydration mismatch, console error, or horizontal page overflow.
- [ ] Performance budget and caching headers reviewed.

## Security and privacy

- [ ] Exact `SECURITY.md` proposal approved before write.
- [ ] Threat-model scope answered and report accepted.
- [ ] CSP, frame, MIME-sniffing, referrer, permissions, and HSTS policy reviewed for the final runtime.
- [ ] No secrets, account IDs, operation bodies, or evidence contents in client bundles or analytics.
- [ ] Dependency and secret scans pass on the release tree.

## Cloudflare release

- [ ] Canonical target selected: Workers Assets or explicit Pages override.
- [ ] Existing project/domain state read live through cfctl.
- [ ] Exact mutation plan reviewed for account, target, cost, permissions, verification, and compensation.
- [ ] Operator explicitly approves the exact operation ID.
- [ ] Apply completes and produces durable evidence.
- [ ] Authenticated live read confirms route, source marker, headers, and critical content.
- [ ] Custom domain/DNS verification complete if in scope.
- [ ] Rollback command/plan and previous known-good artifact are available.

## Operations and learning

- [ ] Monitoring owner and incident path named.
- [ ] Analytics posture is explicitly “none” or approved and documented.
- [ ] First-use protocol and participant recruitment are ready.
- [ ] Release notes reflect only shipped behavior and known limitations.
- [ ] Post-launch review date scheduled.
