# Security Policy

`cfctl` mints, holds, and routes Cloudflare API tokens. Treat anything that touches that flow as security-sensitive.

## Reporting a vulnerability

If you find a security issue — a credential leak, a way to bypass the preview/ack gate, a path traversal in `--value-out`, an injection in any wrapped command — **do not open a public issue**.

Instead, report it privately:

- Open a [private vulnerability report](https://github.com/rogu3bear/cfctl/security/advisories/new) on GitHub, **or**
- Email the maintainer at the address listed on the GitHub profile of the repo owner.

Please include:
- a short description of the issue and its impact,
- a reproduction (commands, configs, or the smallest patch that triggers it),
- the affected version (commit SHA or tag),
- whether the issue is already public anywhere.

You will get an acknowledgement on receipt. A fix or mitigation is coordinated before public disclosure.

## Scope

In scope:
- The `cfctl` runtime (`cfctl`, `commands/`, `lib/`)
- Catalog files in `catalog/` that drive policy
- Backend scripts under `scripts/` when invoked through `cfctl`
- Wrapped `wrangler` and `cloudflared` invocations through `cfctl`
- Token mint, secret-sink, preview, and lock flows

Out of scope:
- Vulnerabilities in upstream `wrangler`, `cloudflared`, `jq`, or `curl` themselves — report those upstream.
- Issues that require an attacker who already has full shell access on the operator's machine.
- Issues that require a Cloudflare API token the operator has not minted via `cfctl token mint`.

## Operator hygiene (not vulnerabilities, but worth saying)

- Never commit `.env` or any file containing a real token.
- Prefer `cfctl token mint --value-out <absolute path>` over `--reveal-token-once`.
- Treat `var/inventory/` and `var/logs/` as potentially sensitive — they record real account state.
- Rotate the master token used to mint scoped tokens on a schedule, and after any suspected exposure.
