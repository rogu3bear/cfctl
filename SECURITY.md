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

v1.3.0 must not be published unless both macOS binaries carry the reviewed
Developer ID Application identity, hardened runtime, secure timestamps, and
accepted Apple notarization receipts. `SHA256SUMS` and commit-bound provenance
must carry Sigstore bundles for the reviewed certificate identity and OIDC
issuer. Reproducible double-builds, checksum verification, and per-binary SPDX
SBOMs remain independent requirements; signatures never replace them. Unsigned
`cargo xtask assemble` outputs are local evidence and must not be published or
represented as a release.

The exact Developer ID authority, TeamIdentifier, Sigstore certificate
identity, and OIDC issuer must be committed here before publication. Until
those non-secret trust roots are present, no downloaded formula or installer
is an authenticated bootstrap path and v1.3.0 remains held from publication.

Machine-read release trust roots (non-secret):

- Developer ID Application identity: `UNBOUND`
- Developer ID TeamIdentifier: `UNBOUND`
- Sigstore certificate identity: `UNBOUND`
- Sigstore OIDC issuer: `UNBOUND`

`cargo xtask release` and `cargo xtask publish` reject `UNBOUND`, missing, or
mismatched values. Provisioning credentials alone cannot bypass this committed
public identity boundary.
