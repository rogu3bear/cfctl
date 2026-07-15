# cfctl v2

`cfctl` is a universal, governed Cloudflare control plane for macOS and Linux.
It is an open-source Rust CLI with no MCP dependency, accepts natural-language
intent through a configured local agent, and exposes deterministic commands
with stable JSON for automation.

```bash
./bootstrap.sh
cfctl catalog sync
cfctl catalog search "Worker secret"
cfctl guide worker-put-script-secret
cfctl "rotate the production Worker secret"
```

## What it covers

Catalog refresh ingests Cloudflare's official OpenAPI schema, OAuth permission
inventory when authenticated, official docs/changelog feeds, installed
Wrangler help, and installed cloudflared help. Every operation is discoverable
and classified as:

- `native`
- `dynamic_api`
- `delegated_cli`
- `governed_ui`
- `blocked`, with an exact reason

The catalog spans control-plane configuration, Workers and Pages, storage and
data, AI, Browser Run, email, media, networking, security, registrar, billing,
analytics, and paid/enterprise features. “Universal” means honest discovery
and classification; entitlement, missing permission, unavailable adapters,
unknown cost, and unsupported verification remain visible blockers.
Catalog sync also joins official product pricing indexes to matching
capabilities. Those references identify usage, subscription, pass-through, or
contract exposure without pretending a variable downstream bill is a hard
execution ceiling. `catalog coverage` reports entitlement metadata, plan-gated
operations, pricing-reference coverage, declared verification and rollback
contracts, and fully complete mutation contracts separately. It also reports
overlapping, stable mutation-gap classes (`risk_unknown`, `cost_unbounded`,
`verification_missing`, and the other execution guards) plus adapters that are
blocked for a reason outside the generic mutation contract. Those stable gap
names and their human-readable forms are searchable directly, so `catalog
search "verification missing"` finds the affected operations without granting
them execution authority.

Verification and rollback strategy names are executable contracts, not prose.
Only strategies implemented by the runtime and valid for the capability's
exact method, identity, and resource shape count as complete. Policy blocks an
unknown or grafted strategy, and the Cloudflare adapter repeats the verifier
check before sending a mutation.

## Public commands

```text
cfctl "<natural-language request>"
cfctl auth login|status|profiles|use|logout|import-global-key
cfctl keys permissions|mint|rotate|revoke
cfctl catalog sync|search|show|changes|coverage
cfctl call <capability-id> [selectors/body]
cfctl guide <capability-id>
cfctl plans show|approve|run|status|resume|rectify
cfctl workspace add|discover|graph|audit
cfctl agents install|doctor|sync
cfctl docs search|changes|coverage
cfctl doctor
cfctl update
cfctl migrate v1
```

Every command has concise human output and stable `--json` output. The public
contracts are `CapabilityV1`, `PlanV1`, `PolicyDecisionV1`, `AgentActionV1`,
`EvidenceV1`, and `ResultEnvelopeV2`.

## Authentication

OAuth Authorization Code with PKCE is the normal lane. Tokens live in Keychain
on macOS or Secret Service on Linux. Each profile/workspace pins an account and
ambiguous selection fails closed.

Until the public cfctl OAuth application is promoted, bring your own Cloudflare
OAuth client:

```bash
cfctl auth login \
  --profile default \
  --client-id "$CFCTL_OAUTH_CLIENT_ID" \
  --scope <scope-id> \
  --account <account-id>
```

The login emits an authorization URL. The static callback displays a one-time
`STATE CODE` value for the CLI completion step. Public clients never embed a
client secret. Refresh and logout/revocation are supported.

An emergency global key can be imported from stdin. It is never selected
silently:

```bash
printf '%s' "$CLOUDFLARE_API_KEY" | \
  cfctl auth import-global-key \
  --profile emergency-global \
  --email you@example.com \
  --stdin
```

## Read and change

```bash
cfctl call zones-get --query name=example.com --json
cfctl guide dns-records-for-a-zone-create-dns-record
cfctl call dns-records-for-a-zone-create-dns-record \
  --selector zone_id=<zone-id> \
  --body-json '{"type":"TXT","name":"_example","content":"hello"}'
```

`guide --json` returns the exact 15-stage lifecycle with contract states,
evidence classes, blockers, safe next actions, and argv arrays. A blocked
capability never receives a runnable `call_argv`; its post-resolution argv is
clearly separated as a template. Token creation is exposed through the
inventory-bound `keys mint` workflow rather than a direct create call.
Account-owned tokens use the account permission inventory. User-owned tokens
require `--user`, use the user permission inventory, and are constrained to one
explicit `--account` resource; wildcard and arbitrary-resource policies are
not accepted.

A mutating `call` creates a hash-bound transaction plan. It does not write
immediately. Review the plan and exact operation ID:

```bash
cfctl plans show <operation-id> --json
cfctl plans approve <operation-id> --yes --json
cfctl plans run <operation-id> --json
cfctl plans status <operation-id> --json
```

Known, scoped, reversible, isolated operations may be policy-authorized to run
without a separate approval. Deletes, purges, identity/security/ownership
changes, external sends, registrar/billing actions, irreversible data changes,
unknown semantics, cross-repository impact, and paid actions require approval.
Paid plans also require `--max-cost CURRENCY:AMOUNT`; unknown or unbounded
downstream cost is blocked even when an official pricing page is available.

Plans bind the derived executable-catalog hash, account, permission lane, exact request,
workspace graph, source configuration, impact, costs, verification,
compensation, and warnings. They expire within 24 hours. Drift invalidates
approval. A hash-chained transaction journal persists the reviewed plan,
approval, consumption, adapter boundary, secret sink, verification, and close
checkpoints. Every checkpoint binds the plan status; apply, sink, and
verification checkpoints also bind non-secret receipt hashes. Changing a
status, returned resource ID, or evidence hash therefore invalidates the
journal, and storage rejects the plan on save or load. A plan durably consumed
before a crash cannot be replayed. The local
durability suite reopens the state store after an injected crash between every
journal transition and proves recovery stops at the last persisted checkpoint.

When a zone-scoped mutation is otherwise complete but its official plan matrix
requires live resolution, `call` reads the exact zone subscription with the
selected credential. Only active `Trial`, `Provisioned`, or `Paid` canonical
Free, Pro, Business, or Enterprise plans (including their explicit partner
variants) are mapped. The resolved capability metadata and normalized receipt
hash enter the plan, and `plans run` repeats the read before durable
consumption. Missing Billing Read access, inactive or unfamiliar plans,
unavailable tiers, and any drift all fail before the Cloudflare mutation
boundary. Account-level subscription lists remain blocked until each
product-scoped subscription can be mapped without ambiguity.

Every executable zone-scoped mutation also performs a Zone Read of the exact
target before planning and again before durable consumption. The returned zone
ID and `account.id` must match the selector and selected account. The normalized
ownership receipt is hash-bound to the plan; missing access, cross-account
targets, substituted responses, and ownership drift fail before mutation.

`cfctl keys mint` validates every selected permission-group ID against a fresh,
owner-specific live inventory before it creates a plan. The plan binds only the
normalized ID, name, category, and scopes for the selected groups plus the
live-read evidence hash; it never copies arbitrary inventory fields. Each
selected group must explicitly support `com.cloudflare.api.account`, and the
policy must target exactly the requested account. Execution repeats the same
owner-specific inventory read before durable consumption and rejects renamed,
rescoped, missing, duplicate, cross-account, wrong-owner, or widened policy
input. Direct token-create calls cannot bypass this workflow. Use `--user` for
a user-owned token; omission selects the account-owned endpoint.

Access service tokens use separate, exactly allowlisted account- and zone-scoped
creation lifecycles. Each accepts only `name` and optional `duration`, requires
`Access: Service Tokens Write`, writes the returned `client_id` and
`client_secret` together as a mode-0600 JSON credential bundle, and verifies
the exact returned resource by ID and planned metadata. If that verification
needs rectification, cfctl can derive a separate reviewed exact-scope delete
plan. The published account-level rotate endpoint remains blocked because
Cloudflare's current operation schema does not declare its required permission
lane; cfctl does not borrow authority from either create operation.

Account- and zone-scoped Access service-token updates are separate exact
operation/path/product/selector contracts, each narrowed to `name` and
`duration`. cfctl excludes `client_secret_version`, which Cloudflare documents
as a rotation trigger, and `previous_client_secret_expires_at`, which changes
the old-secret grace period. The exact same-scope token is read back after
update. Because changing duration resets expiration relative to the update,
cfctl does not claim it can restore the exact prior expiration; any corrective
update is a separate reviewed plan.

Refreshing an Access service token is a separate, body-free irreversible lane.
Cloudflare documents it as a one-year lifetime extension relative to refresh
time. cfctl requires the exact token ID and returned future `expires_at` to
match an immediate detail readback, but does not claim the prior expiration can
be restored. Shortening or otherwise correcting lifetime requires another
reviewed operation from trusted evidence.

When a token or DNS-record creation receipt proves the returned resource ID
and the catalog declares a compensating delete, `plans rectify` can derive a
separate hash-bound revoke/delete plan. It never runs that plan automatically:
the destructive compensation has its own operation ID, review, approval,
execution, and not-found verification. Core DNS create, patch, replace, and
delete use exact record-detail readbacks; create/update verify every planned
field without copying record contents into the verification basis. DNS batch,
import, scan, and review operations remain blocked pending their distinct
operation contracts.

For other creates, cfctl only derives a lifecycle when the official success
schema declares a string `result.id` and exactly one same-product child path
supports both GET and DELETE. The plan binds that path, response pointer, and
capability IDs. Live verification reads the returned resource and compares
every planned field; rectification can draft only the exact bound delete.
Ambiguous paths, undocumented identities, unknown cost, and unresolved risk or
entitlement stay blocked.

DNS record API mutations have a known zero direct incremental charge, while
Enterprise DNS query volume and the Workers, storage, traffic, or other
products reached through the record can have plan-specific downstream pricing.
The catalog models those facts separately and links the official DNS product
and pricing FAQ; zero direct charge is not a promise that downstream usage is
free.

Generated write capabilities stay blocked until risk and effect are classified,
incremental cost and plan entitlement are known, permissions are declared, and
operation-specific verification plus rollback or irreversibility behavior are
implemented. This makes catalog coverage broader than executable write
coverage by design. The catalog preserves the upstream OpenAPI `source_hash`
separately; approvals use the derived `schema_hash`, so local adapter or safety
contract changes invalidate an older approval even when the upstream schema is
unchanged.

PUT/PATCH settings that do not end in a resource selector gain field-level
readback only when an identical-path GET from the same product officially
declares every writable request field under `result`. Bulk arrays and partial
response schemas stay blocked, and restoration still requires a separately
reviewed plan because no pre-change snapshot is captured.

## Secrets

Secret inputs enter through stdin and become opaque platform-key-store
references. Secret-producing calls require a new file sink:

```bash
cfctl call cloudflare-tunnel-get-a-cloudflare-tunnel-token \
  --selector account_id=<account-id> \
  --selector tunnel_id=<tunnel-id> \
  --value-out /tmp/tunnel-token
```

The destination is created mode 0600 on Unix. Raw values never enter stdout,
plans, logs, delegated subprocess receipts, or evidence.

OAuth client secrets use an explicit two-phase cutover. `oauth-clients-rotate-secret`
requires a new sink and live one-secret pre-state; after dependents are verified,
`oauth-clients-delete-rotated-secret` is reviewed and approved separately. Both
plans recheck the exact client state before consumption and verify the expected
`has_rotated_secret` transition afterward.

## Workspaces and agents

Registered roots bound all discovery:

```bash
cfctl workspace add /absolute/repository/root --account <account-id>
cfctl workspace discover --json
cfctl workspace graph --json
cfctl workspace audit --json
```

Discovery inventories Git repositories even when they contain no Cloudflare
configuration. Supported files include Wrangler TOML/JSON/JSONC, Terraform
HCL/JSON, and Pulumi YAML. Each is linked to catalog targets with
current-content, `HEAD`-content, and exact
worktree-diff hashes so dirty or unmanaged dependencies remain visible in a
plan. Terraform and Pulumi runtime links require literal properties specific to
the declared resource type; dynamic expressions and Wrangler binding names are
kept as local symbols, not Cloudflare resource identities. The fixture matrix
includes staged, unstaged, and untracked configuration,
configless repositories, and duplicate repository basenames without collapsing
their canonical identities.

Install managed instructions for detected local agents:

```bash
cfctl agents install --all-detected
cfctl agents doctor
```

Natural language launches the configured agent once. The
`CFCTL_AGENT_SESSION` marker prevents recursion. Agents translate intent into
catalog searches and deterministic commands; model output never grants
authority or directly mutates Cloudflare.

Browser or Computer Use is available only for cataloged `governed_ui`
capabilities after API/CLI coverage cannot finish the task. UI actions bind the
account and target, redact credentials, capture before/after evidence, and obey
the same approval and verification rules.

## Evidence and migration

Meaningful operations leave redacted, content-addressed local evidence.
Evidence class distinguishes source config, live reads, plans, applies,
post-change verification, agent actions, and local proof. Artifact presence is
not verification.

`cfctl migrate v1` copies safe desired state and non-secret evidence into
content-addressed imports. It skips secret-shaped paths/content and never
imports credentials implicitly. The original dirty shell runtime was frozen
before cutover in the gitignored private v1 archive for the one-release
compatibility window.

## Development and release

Rust 1.93 is pinned. The local proof lane is:

```bash
cargo xtask verify
```

The proof host also needs `cargo-deny` and Gitleaks. The lane rejects yanked
dependencies, unreviewed licenses or sources, unversioned dependency edges,
and secret findings across the complete Git history. Duplicate transitive
versions remain visible as warnings with their inverse dependency trees.

The assembly lane builds Apple arm64/x86_64 and Linux musl arm64/x86_64 twice,
compares hashes, creates SPDX SBOMs and provenance, and renders the Homebrew
formula and checksum-verifying Linux installer. The release lane repeats that
proof and signs the manifests before they can be uploaded to an existing
GitHub release:

The local release host additionally needs the four Rust standard-library
targets, Zig and `cargo-zigbuild`, `cargo-auditable` 0.7.5, Syft, Cosign,
Xcode command-line tools, an explicit Developer ID Application identity, and a named
`notarytool` Keychain profile. The auditable build metadata is what lets each
platform SBOM enumerate the actual Rust dependency graph instead of treating
`cfctl` as one opaque file.

```bash
cargo xtask assemble
cargo xtask release \
  --certificate-identity '<expected Fulcio identity>' \
  --certificate-oidc-issuer '<expected OIDC issuer>' \
  --macos-signing-identity 'Developer ID Application: Example Corp (TEAMID)' \
  --apple-notary-profile '<Keychain profile name>'
cargo xtask publish \
  --tag v2.0.0-alpha.1 \
  --certificate-identity '<expected Fulcio identity>' \
  --certificate-oidc-issuer '<expected OIDC issuer>' \
  --macos-signing-identity 'Developer ID Application: Example Corp (TEAMID)'
```

An account-backed disposable token smoke test is intentionally separate from
the local proof lane because it mutates a real account. After selecting an
explicit disposable account/profile and reviewing its acknowledgement gate,
the operator can run `tests/account-backed-smoke.sh`. It mints, rotates,
revokes, and verifies one short-lived token and attempts exact-ID revocation as
compensation if interrupted.

```bash
CFCTL_PUBLIC_CONTRACT_ACCOUNT_ID='<disposable-account-id>' \
CFCTL_PUBLIC_CONTRACT_PROFILE='<selected-profile>' \
CFCTL_PUBLIC_CONTRACT_PERMISSION_GROUP_ID='<reviewed-permission-group-id>' \
CFCTL_PUBLIC_CONTRACT_CONFIRM='mint-rotate-revoke-disposable-token' \
  tests/account-backed-smoke.sh
```

`assemble` deliberately stops before identity-bearing Apple or Sigstore
activity, and its rendered Linux installer refuses to run. `release` requires
a clean source commit, signs both macOS binaries
with hardened runtime and secure timestamps, notarizes them through the named
Keychain profile, records hash-bound `Accepted` receipts, refreshes their SBOMs
and Homebrew hashes, signs checksums and provenance, and verifies every
identity again. A notary submission ID is written before waiting, so an
interrupted external operation leaves a durable receipt under
`target/release-proof/notary/`. `publish` accepts only the complete
four-platform artifact set, rechecks Apple signatures, notarization receipts,
checksums, provenance, and Sigstore identities, and uploads one asset at a time
to an empty draft release without clobbering. If an upload fails, it removes
only the assets from that failed attempt. Making the draft public remains a
separate operator action.

The published Linux installer requires Cosign. It verifies the downloaded
checksum manifest against the exact Fulcio identity and OIDC issuer rendered by
the release operator, then checks the selected binary against both that signed
manifest and the installer-embedded architecture hash. It has no checksum-only
fallback.

GitHub-hosted Rust builds are intentionally absent.

## External activation boundary

`cfctl.io` registration, site publication, publisher-domain verification,
permanent Cloudflare OAuth promotion, and public release publication require
explicit operator action. The project/privacy/terms/logo/callback site is ready
under `site/`; these external steps are not silently performed or claimed.

- [Quickstart](QUICKSTART.md)
- [Architecture](docs/v2-architecture.md)
- [Runtime policy](docs/runtime-policy.md)
- [Security contract](docs/v2-security.md)
- [Agent landing](docs/agent-landing.md)
- [v1 parity and shell-removal audit](docs/v1-parity.md)
- [v2 stacked review, merge, and rollback runbook](docs/v2-pr-sequence.md)
- [Rust clean-break ADR](docs/architecture/adr/0001-rust-clean-break.md)
- [Risk-based approval ADR](docs/architecture/adr/0002-risk-based-approval.md)
