# Draft mainline release notes — 2026-08-05

Status: repository mainline notes, not a public version announcement or deployment claim.

## A quieter credential path

`cfctl` now keeps using its governed fallback credential store once that store is active. Ordinary commands no longer reopen macOS Keychain merely to discover that the fallback remains authoritative. Operators still have an explicit repair path when they intentionally want to test or restore Keychain.

The source tree makes the installed revision visible through `cfctl doctor`,
which provides the build-identity check required before any later live work.
This draft does not claim that the accumulator branch is installed or that an
authenticated provider read has run from it.

## New governed capabilities

- Pages direct uploads and custom-domain workflows now carry catalog, guide, plan, verification, and compensation contracts.
- Quick tunnels can be created through a bounded temporary-endpoint contract.
- WebSockets settings can be read and changed through the governed zone-setting lifecycle.

Each write remains plan-first. Landing code on `main` does not mean an account mutation, website deployment, or public release occurred.

## Documentation correction

The security guide now agrees with runtime policy: the fallback store is sticky after activation, and Keychain repair is an explicit operator action rather than a routine credential probe.

## Upcoming website preview

The former static site template has been replaced locally by a standalone
Leptos 0.8 application for Cloudflare Workers and Workers Assets. Its Control
Ledger design explains the ordered read/plan/admit/execute/verify boundary,
adds a bounded first-read guide, preserves direct privacy and terms routes, and
hardens the OAuth callback as a browser-only, query-erasing, one-copy bridge.

The v1 website has no user accounts, forms, database, object storage,
analytics, runtime secrets, or third-party scripts. Content is useful SSR HTML;
only command copy and the callback bridge hydrate. This section is preview
notes for an uncommitted, undeployed tree—not a public launch claim.

## Operator impact

- If you already use fallback credentials, ordinary `auth status` and governed calls should no longer trigger repeated Keychain password prompts.
- If a call returns an authorization error, use the capability-specific governed command and verify that the active token has the required scope; do not broaden credentials merely to silence the error.
- Use `cfctl doctor` to confirm the installed source revision and active secret backend when behavior differs between checkouts or hosts.

## Evidence and limits

The website exists only as source and local build artifacts until the current
accumulator candidate passes its complete proof lane. No Cloudflare deployment
plan has been created, no provider mutation has run, no live edge readback
exists, and no public release is claimed.
