# Security Policy

`cfctl` mints, holds, rotates, and revokes Cloudflare API tokens and can plan
changes across an account. Treat authentication, catalog policy, planning,
execution, verification, evidence, installers, and release provenance as
security-sensitive boundaries.

## Reporting a vulnerability

If you find a security issue — a credential leak, a way to bypass plan approval (`cfctl plans approve <operation-id> --yes` followed by `cfctl plans run`), a path traversal in `--value-out`, an injection in any wrapped command — **do not open a public issue**.

Instead, report it privately:

- Open a private vulnerability report through the repository's GitHub security advisory page, **or**
- Email the maintainer at the address listed on the GitHub profile of the repo owner.

Please include:
- a short description of the issue and its impact,
- a reproduction (commands, configs, or the smallest patch that triggers it),
- the affected version (commit SHA or tag),
- whether the issue is already public anywhere.

You will get an acknowledgement on receipt. A fix or mitigation is coordinated before public disclosure.

## Scope

In scope:

- The Rust runtime and public contracts under `crates/`.
- Catalog ingestion, generated capability metadata, and local safety
  contracts that control execution authority.
- OAuth, API-token, Keychain, Secret Service, secret-input, and secret-output
  paths.
- Plan approval, account and target binding, transaction journals, crash
  recovery, operation-specific verification, and compensation planning.
- Governed Wrangler, cloudflared, and UI handoffs.
- Workspace discovery, IaC parsing, exact diffs, installers, signing,
  provenance, and publication tooling.

Out of scope:

- Vulnerabilities in upstream Cloudflare products or third-party tools
  themselves; report those upstream.
- Issues that require an attacker who already has full shell access on the operator's machine.
- Unsupported local modifications that deliberately bypass the reviewed
  binary and its policy.

## Operator hygiene (not vulnerabilities, but worth saying)

- Never commit a real credential, account identifier, or private evidence.
- Use `--value-out` for secret-producing calls; cfctl refuses stdout delivery
  and creates only a new mode-0600 file.
- Keep profiles pinned to one account and use the global-key profile only as
  an explicit emergency lane.
- Treat local state and redacted receipts as sensitive operational metadata.
- Rotate credentials on a schedule and immediately after suspected exposure.

## Source and dependency proof

`cargo xtask verify` is the canonical local proof. It includes formatting,
Clippy with warnings denied, the complete test suite, catalog/source-contract
checks, `cargo deny check`, and a full-history Gitleaks scan.

`deny.toml` denies yanked crates, unreviewed licenses, unknown registries and
Git sources, and wildcard dependency requirements. Internal path dependencies
carry the exact workspace version, which the source-contract check enforces by
equality — Cargo alone would accept a stale pin, because the bumped crate still
satisfies it. Duplicate transitive versions remain warnings with their
dependency trees; they are not hidden by blanket skips.

`.gitleaksignore` may contain only exact reviewed fingerprints. Never suppress
a whole rule, path, commit, or entropy class to make the gate green.

These checks are local proof. They do not prove that an account mutation,
signature, notarization, upload, deployment, domain verification, or OAuth
promotion occurred.

Releases are unsigned by operator decision: integrity is checksum-based, so
verify every download against the release's `SHA256SUMS`. Each binary is
reproducible from the tagged source and carries an SPDX SBOM.
