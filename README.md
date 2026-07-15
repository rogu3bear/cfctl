# cfctl v2

`cfctl` is a universal, governed Cloudflare control plane for macOS and Linux.
It is an open-source Rust CLI with no MCP dependency, accepts natural-language
intent through a configured local agent, and exposes deterministic commands
with stable JSON for automation.

```bash
./bootstrap.sh
cfctl catalog sync
cfctl catalog search "Worker secret"
cfctl guide workers-secrets-put-secret-value
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
operations, pricing-reference coverage, and complete mutation contracts
separately.

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
cfctl call zones-list-zones --query name=example.com --json
cfctl guide dns-records-for-a-zone-create-dns-record
cfctl call dns-records-for-a-zone-create-dns-record \
  --selector zone_id=<zone-id> \
  --body-json '{"type":"TXT","name":"_example","content":"hello"}'
```

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

When a token or DNS-record creation receipt proves the returned resource ID
and the catalog declares a compensating delete, `plans rectify` can derive a
separate hash-bound revoke/delete plan. It never runs that plan automatically:
the destructive compensation has its own operation ID, review, approval,
execution, and not-found verification. Core DNS create, patch, replace, and
delete use exact record-detail readbacks; create/update verify every planned
field without copying record contents into the verification basis. DNS batch,
import, scan, and review operations remain blocked pending their distinct
operation contracts.

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
plan. The fixture matrix includes staged, unstaged, and untracked configuration,
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

The release lane builds Apple arm64/x86_64 and Linux musl arm64/x86_64 twice,
compares hashes, creates SPDX SBOMs and provenance, renders the Homebrew formula
and checksum-verifying Linux installer, signs manifests, and can upload to an
existing GitHub release:

```bash
cargo xtask release
cargo xtask publish --tag v2.0.0
```

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
- [Rust clean-break ADR](docs/architecture/adr/0001-rust-clean-break.md)
- [Risk-based approval ADR](docs/architecture/adr/0002-risk-based-approval.md)
