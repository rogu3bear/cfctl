# Draft mainline release notes — 2026-08-05

Status: repository mainline notes, not a public version announcement or deployment claim.

## A quieter credential path

`cfctl` now keeps using its governed fallback credential store once that store is active. Ordinary commands no longer reopen macOS Keychain merely to discover that the fallback remains authoritative. Operators still have an explicit repair path when they intentionally want to test or restore Keychain.

The installed build now reports its exact source revision in `cfctl doctor`, making stale-binary diagnosis easier. The repaired build was locally installed and verified with both credential status and an authenticated D1 database-list read. Secret values were not printed or copied into repository files.

## New governed capabilities

- Pages direct uploads and custom-domain workflows now carry catalog, guide, plan, verification, and compensation contracts.
- Quick tunnels can be created through a bounded temporary-endpoint contract.
- WebSockets settings can be read and changed through the governed zone-setting lifecycle.

Each write remains plan-first. Landing code on `main` does not mean an account mutation, website deployment, or public release occurred.

## Documentation correction

The security guide now agrees with runtime policy: the fallback store is sticky after activation, and Keychain repair is an explicit operator action rather than a routine credential probe.

## Operator impact

- If you already use fallback credentials, ordinary `auth status` and governed calls should no longer trigger repeated Keychain password prompts.
- If a call returns an authorization error, use the capability-specific governed command and verify that the active token has the required scope; do not broaden credentials merely to silence the error.
- Use `cfctl doctor` to confirm the installed source revision and active secret backend when behavior differs between checkouts or hosts.

## Evidence and limits

The combined repository proof passed formatting, Clippy with warnings denied, all tests, dependency policy, secret scanning, and a clean build before `main` was pushed. The installed keyring repair was then verified by an authenticated live read. These notes do not claim that the new website exists, that Cloudflare infrastructure was mutated, or that a public release was published.
