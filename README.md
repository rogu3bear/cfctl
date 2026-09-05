# cfctl v2

`cfctl` is a governed Cloudflare control plane for macOS and Linux: an
open-source Rust CLI that makes every change to your Cloudflare account
reviewable before it happens, and provable after.

Cloudflare's API will let anything holding a token delete a zone, purge a
cache, or rotate a secret in one unreviewed call — and an agent driving that
API is one bad inference away from doing it. cfctl puts a hash-bound plan
between intent and mutation: reads run freely, writes become a reviewed plan
you approve by exact operation ID, and the result is verified against live
Cloudflare state rather than assumed from a 200 response.

It has no MCP dependency, accepts natural-language intent through a local
agent, and every command emits stable JSON for automation.

- [Quickstart](QUICKSTART.md) — install, first commands, first governed write
- [Operator runbook](docs/runbooks/cfctl.md) — the full command lifecycle
- [Runtime policy](docs/runtime-policy.md) — what needs approval, and why
- [Security contract](docs/v2-security.md) — secrets, hashing, invariants
- [Architecture](docs/v2-architecture.md) — crates, boundaries, trust sequence
- [Telemetry control plane](docs/telemetry-control-plane.md) — GraphQL, bounded queries, observability, Logpush, and security response
- [Agent landing](docs/agent-landing.md) — first-load doctrine for agents
- [Contributing](CONTRIBUTING.md) — dev setup, proof lane, release lanes

## Install

```bash
./bootstrap.sh
cfctl version --json
cfctl doctor --json
```

`bootstrap.sh` requires a checkout clean of tracked and untracked non-ignored
files and proves the installed binary is the exact `HEAD` commit. Both doctors
must report the PATH entry resolving to the running executable; a different or
missing PATH binary and drifted agent instructions are unhealthy states, not
warnings.

## The governed loop

Every mutation follows one path — deterministic resolution, a reviewed
hash-bound plan, explicit or policy authority, one Cloudflare boundary, then
operation-specific verification:

```mermaid
flowchart TD
    I[Intent] --> R["cfctl resolve"]
    R --> C[Selected capability]
    C --> G["cfctl guide"]
    G --> CALL["cfctl call"]
    CALL -->|read| EV[Redacted live evidence]
    CALL -->|write| P[Fully pinned PlanV2]
    P --> POL{Policy engine}
    POL -->|narrow safe class| RUN["cfctl plans run"]
    POL -->|everything else| APR["cfctl plans approve --yes"]
    APR --> RUN
    RUN --> B[One Cloudflare boundary]
    B --> V[Operation-specific verification]
    V --> DONE[Evidence and journal]
```

<!-- BEGIN CFCTL GENERATED: system-guide -->
## How cfctl works

cfctl is a local-first, catalog-driven control plane: it separates intent, live reads, durable authority, one Cloudflare boundary, verification, and evidence.

**Will this mutate Cloudflare now?** Discovery, guides, workspace inspection, and read capabilities do not write Cloudflare. A mutating `cfctl call` creates a plan; `cfctl plans run` is the normal write boundary. A token command with `--under-policy` may plan and run in one invocation only under an explicitly approved standing authority. Agent output, guide output, and approval alone do not mutate Cloudflare.

**What grants authority?** The deterministic policy engine grants automatic admission only to the narrow safe class. Otherwise authority is either explicit approval of one reviewed operation ID or explicit approval of one bounded standing token policy. A model never grants authority.

**What is persisted?** Under its managed state root, cfctl persists profile metadata, the live CapabilityV1 catalog and official-doc caches, workspace registrations and imports, plans, approval and admission checkpoints, transaction journals, standing-authority records, locks, and redacted evidence. Credential values remain in the platform secret store or an explicit mode-0600 sink. The source checkout's compat/v1 tree is inert migration evidence, not runtime state or a live catalog.

**What happens after a failure or crash?** Once consumption or a boundary attempt is durable, cfctl never guesses that replay is safe. Inspect `plans status`; use `plans rectify` to reconcile durable receipts and verification without replaying the original Cloudflare mutation.

**What should I do next?** Run `cfctl version --json` and both doctors before work; running-build, PATH-build, or managed-instruction drift is unhealthy. Read token permissions only with an explicit account context (`keys permissions --account`, adding `--user` only to select user ownership). Nested fixture basenames are skipped during broader workspace scans; fixture directories are opt-in roots and must be registered directly. Then resolve the intent deterministically (`cfctl resolve`), browse with `cfctl catalog search` only when exploring, and inspect the selected capability and its capability-specific guide before calling it.

### Lifecycle

1. **Orient** (`none`) — Check running and PATH build identity, local state, credentials, catalog health, and agent integration.
2. **Discover** (`none`) — Resolve the intent to the catalog-selected capability and adapter; browse the catalog when exploring.
3. **Read** (`read`) — Inspect exact live Cloudflare state and registered-workspace impact. Durable state: redacted live-read and source-config evidence
4. **Plan** (`none`) — Bind the request, account, catalog, impact, cost, verification, and compensation contracts. Durable state: canonical pinned PlanV2, compatible PlanV1 journal projection, and PlanPrepared checkpoint
5. **Admit** (`none`) — Apply policy, bind any explicit approval, acquire locks, and recheck drift. Durable state: approval, standing reservation, and consumption checkpoints
6. **Execute** (`write`) — Persist the boundary attempt, then cross exactly one catalog-selected adapter boundary. Durable state: boundary-attempt and response checkpoints
7. **Verify** (`read`) — Run the operation-specific verifier or record why rectification is required. Durable state: sink and verification receipts
8. **Close or rectify** (`none`) — Close with evidence or reconcile the durable journal; any compensation is a new plan with independent authority. Durable state: terminal plan status and content-addressed evidence

### Commands

```bash
cfctl version --json
cfctl doctor --json
cfctl agents doctor --json
cfctl keys permissions --account <account-id> --json
cfctl keys permissions --user --account <account-id> --json
cfctl guide --topic standing-authority --json
cfctl resolve <intent> --json
cfctl catalog search <intent> --json
cfctl catalog show <capability-id> --json
cfctl guide <capability-id> --json
cfctl call <capability-id> --json
cfctl plans show <operation-id> --json
cfctl plans approve <operation-id> --yes --json
cfctl plans run <operation-id> --json
cfctl plans status <operation-id> --json
cfctl plans rectify <operation-id> --json
```
<!-- END CFCTL GENERATED: system-guide -->

## Public commands

The public grammar is:

```text
cfctl <area> <action> [target] [flags]
```

The area stays first and the action says what happens. Direct operations such
as `resolve`, `guide`, and `call` omit the area. Run `cfctl commands` to read
the complete executable command map at once, `cfctl commands --json` to consume
the same map as data, or `cfctl <command path> --help` for exact arguments.
The map is generated from the Clap command tree, so this document does not
maintain a second command registry.

Open-ended intent remains available as `cfctl "<natural-language request>"`.
Existing v2 paths remain compatible; the command map includes newer paths such
as `auth evidence-key init-preview`, `auth evidence-key adopt-preview`,
`auth evidence-key adopt-plan create`, `auth evidence-key recover-preview`,
`auth evidence-key recover-plan create`,
`auth repair-keychain-access`,
`keys renew-analytics-profile`, and
`plans bundle` that a hand-maintained list could omit.

Every command has concise human output and stable `--json` output, shaped by
the public contracts `BuildInfoV1`, `CapabilityV1`, `CapabilityGuideV1`,
`GuideTopicDocumentV1`, `PlanV1`, `PolicyDecisionV1`, `AgentActionV1`,
`EvidenceV1`, and `ResultEnvelopeV2`.

## Authenticate

Day-to-day auth is a scoped API token, imported only through stdin — never
argv — and pinned to one account:

```bash
printf '%s' "$CLOUDFLARE_API_TOKEN" | \
  cfctl auth import-api-token --account <account-id> --stdin
```

The token lives in the platform keyring (Keychain on macOS, Secret Service on
Linux) and falls back to a mode-0600 file store when the keyring is
unavailable; `cfctl doctor` reports which backend is active.

Qualifying local evidence uses a separate, explicitly selected integrity key.
The platform mode never automatically falls back to a file: inspect the exact initialization transition with
`cfctl auth evidence-key init-preview --json`, initialize it explicitly with
`init`, inspect it with `status`, rotate to a new signing generation with
`rotate`, and retire an inactive generation only when cfctl reports that no
authenticated local artifact still depends on it. The preview discloses
backend, custody, state-root transition, verification-generation behavior, and
recovery semantics without creating a key or exposing key bytes.

For routine use without platform credential dialogs, prepare an explicit fresh
local runtime with `cfctl auth evidence-key private-preview --json`, inspect
its carried/missing profile IDs and local trust boundary, then run the returned
`private-activate <plan-id> --yes --json` command. The same flow works on a fresh
host before importing its first scoped token. It creates a fresh authority,
keeps old state and history intact, and persistently selects private local
credentials and evidence storage. `status` and `doctor` report `private_file`.
No continuity with old signing keys or approval authority is claimed. Software
running as your OS user can access these files; filesystem privacy does not
isolate mutually distrustful programs running as the same user.

Initialization crosses two independent custody domains: the platform registry
and the filesystem state-root marker. No transaction spans both, so `init`
publishes a private initialization intent naming the exact state root before
creating the authority, and retires that intent only after the marker reads
back. If the process dies between the two writes, the next `init` recognizes
the registry as this installation's own interrupted crossing and resumes it
forward by creating only the missing marker, preserving the exact authority and
its generation. Resumption requires the published intent to name the registry
that is actually present and requires zero authenticated local artifacts; an
intent that disagrees with the registry fails closed rather than being
reconciled by inference. A valid registry with no such intent is not
resumable — it is an authority of unknown provenance, and remains an adoption
question rather than an initialization one.

If the exact sole canonical platform registry is already valid while its local
marker and all authenticated storage-v2 artifacts are absent, use
`adopt-preview` for a strictly read-only classification. `adopt-plan current`
and `adopt-plan status` remain read-only so historical records can be inspected,
and `adopt-plan revoke` remains limited to a plan that has not crossed.

`adopt-plan create` and `adopt <plan-id> --yes` are intentionally unavailable
in this release. Both fail with
`CFCTL_AUTH_INSTALLED_IDENTITY_RECEIPT_REQUIRED` before plan persistence,
filesystem-marker creation, private crossing-seal publication, or terminal
completion. Signed publication and installation may proceed independently, but
adoption must wait for a separately reviewed producer and consumer for an
authenticated installed-identity receipt. The CLI accepts no raw source,
artifact, architecture, CDHash, algorithm, or provenance flags as authority.

Receipt-less historical plan records remain readable but non-executable. The
preserved state machine also rejects a record-backed `allocating` pointer as
crossing authority: it cannot publish a seal, project `marker_crossed`, complete,
or enable ordinary evidence authentication. This release claims no adoption
outcome.

A valid registry that cannot be resumed and cannot be adopted is not a dead end.
`auth evidence-key reset --yes` discards it and initializes a fresh authority.
Adoption *inherits* an existing authority, which is why it must authenticate the
identity of the code asking; reset inherits nothing, claims no lineage, and
produces exactly what a clean host produces, so it requires no installed-identity
receipt. It is admissible only when the state-root marker is absent, the registry
is a fresh single-generation authority in direct platform custody, and zero
authenticated descriptors and proofs exist. That last condition is the point: an
authority nothing depends on can be discarded without losing anything, and reset
refuses rather than orphaning a single authenticated artifact. The discarded
registry is removed through the managed platform-keyring teardown, never by hand.

If the sole canonical platform registry is malformed while the filesystem
marker and authenticated storage-v2 artifacts are absent, use
`recover-preview` for a strictly read-only classification and byte count. It
does not disclose raw registry material, a digest, a secret-derived identity,
or a deterministic execution handle. A separate `recover-plan create` writes
a short-lived private intent to the platform keyring and returns only a random
opaque plan ID; inspect or revoke that plan with `recover-plan status|revoke`,
without another confirmation prompt. Only the transition that quarantines and
replaces the protected registry requires `recover <plan-id> --yes`. Recovery preserves the original
bytes in private quarantine before publishing a fresh chunked authority and
resumes the same plan forward after an interrupted transition. Quarantine
retirement is a separate lifecycle and legacy evidence remains historical and
nonqualifying.

Two things that commonly bite:

- If a wrapper routes stdin through `cargo`, pass a new mode-0600 file with
  `--value-in` instead, so the secret never touches stdin.
- `CFCTL_FORCE_IPV4=1` pins outbound calls to an IPv4 source, which an
  IP-allowlisted token needs when the host default-routes over IPv6.

OAuth with PKCE is available when you have a Cloudflare OAuth client
(`--client-id` / `CFCTL_OAUTH_CLIENT_ID`). An emergency global key can be
imported with `cfctl auth import-global-key`, and is never selected silently.

## Read, then change

Reads run immediately and leave redacted evidence:

```bash
cfctl call zones-get --query name=example.com --json
```

A mutating `call` writes nothing. It produces a hash-bound plan you review by
exact operation ID:

```bash
cfctl guide dns-records-for-a-zone-create-dns-record
cfctl call dns-records-for-a-zone-create-dns-record \
  --selector zone_id=<zone-id> \
  --body-json '{"type":"TXT","name":"_example","content":"hello"}'

cfctl plans show <operation-id> --json
cfctl plans approve <operation-id> --yes --json
cfctl plans run <operation-id> --json
```

Plans expire within 24 hours and any relevant drift invalidates approval. A
hash-chained transaction journal persists every checkpoint from reviewed plan
through close, so a plan consumed before a crash is never replayed — inspect
`plans status` and reconcile with `plans rectify`. If you approved something
you no longer want, `plans cancel <operation-id>` retires it immediately
rather than leaving latent authority to expire.

A narrow safe class of known, scoped, reversible operations runs without
separate approval. Deletes, purges, identity and ownership changes, external
sends, billing actions, irreversible changes, and anything paid always require
it — see [runtime policy](docs/runtime-policy.md) for the exact contract, and
[the security contract](docs/v2-security.md) for per-capability invariants.

Secret outputs never reach stdout, plans, logs, or evidence. They require a
new file sink, created mode 0600:

```bash
cfctl call cloudflare-tunnel-get-a-cloudflare-tunnel-token \
  --selector account_id=<account-id> \
  --selector tunnel_id=<tunnel-id> \
  --value-out /tmp/tunnel-token
```

Token creation is exposed only through the inventory-bound `keys mint`
workflow, never a direct create call.

## What cfctl refuses to do

Expect to meet the wall early, and read it as the design working. cfctl
catalogs every Cloudflare operation but executes a mutation only when its
contract is fully known — risk, effect, cost, permission, entitlement,
verification, and rollback or explicit irreversibility. Most mutating
operations are blocked on incomplete upstream metadata — the executable core is
a deliberate minority — and cfctl will not fabricate a permission or a price to
close that gap: a guessed one is worse than an honest block. The live ratio is
whatever `catalog coverage` reports; this file does not restate a number it
cannot keep true.

```bash
cfctl catalog coverage --json          # what is executable, and what is not
cfctl call workflow.telemetry.audit-account --json # bounded proof preview; blocked/gapped steps have no runnable call
cfctl catalog show <capability-id>     # exactly which fields are missing
```

Blocked capabilities stay discoverable and explain themselves. Most of the
root cause is upstream and filed in
[upstream schema gaps](docs/upstream-schema-gaps.md).

## Workspaces and agents

Registered roots bound all discovery — cfctl never scans outside them:

```bash
cfctl workspace add /absolute/repository/root --account <account-id>
cfctl workspace remove /absolute/repository/root
cfctl workspace discover --json
cfctl workspace audit --json
```

Removing a root stops future discovery and removes its account pin while
preserving historical graph and evidence records. Discovery excludes nested
generated, cache, fixture, vendor, and nested-repository paths unless they are
registered directly. It inventories Git repositories even when they carry no Cloudflare
configuration, and links Wrangler TOML/JSON/JSONC, Terraform HCL/JSON, and
Pulumi YAML to catalog targets with current-content, `HEAD`-content, and exact
worktree-diff hashes, so dirty or unmanaged dependencies stay visible in a
plan.

The registry is a rebuildable local projection, not a replacement authority:

```bash
cfctl registry sync --json
cfctl registry coverage --json
cfctl registry list --json
cfctl registry diff --json
```

Catalog operations, source configuration, desired declarations under
`CFCTL_HOME/config/registry/declarations/`, live observations, and evidence
remain distinct. Coverage stays `partial` whenever a live normalization
provider, permission, or fresh observation is missing. `registry rebuild`
creates a consistent SQLite backup before reconstructing derived rows.

Admission policy is staged, reviewed, approved, and atomically activated as a
separate local policy input. A bundle can tighten the compiled hard safety
floor but cannot override ambiguity, incomplete contracts, unknown cost,
secret hazards, stale observations, or pinned-state drift:

```bash
cfctl policy admission list --json
```

New mutation plans carry a PlanV2 pin set while the PlanV1 body remains
readable for compatibility. Historical unconsumed PlanV1 mutations must be
replanned before approval or execution.

Events are durable reconciliation triggers, never observed resource truth:

```bash
cfctl events sources --json
cfctl events status --json
cfctl events bridge inspect --json
cfctl call events-consume-queue-batch \
  --selector account_id=<account-id> --selector queue_id=<queue-id> \
  --selector subscription_id=<subscription-or-webhook-id> \
  --body-json '{"batch_size":100,"visibility_timeout_ms":60000}' --json
```

The synthetic event-batch capability is the only Queue pull/ack lane. Each
batch is one fully pinned ordinary PlanV2 with explicit approval and the
reviewed USD 0.00016 maximum; raw pull and acknowledgement capabilities remain
blocked. Event evidence and derived reconciliation jobs commit atomically
before exact lease acknowledgement. The inbound Worker under
`bridge/event-ingress` is managed with Bun (`bun install --frozen-lockfile`,
`bun run check`); preparing its manifest does not deploy it.

```bash
cfctl agents install --all-detected
cfctl agents doctor
```

Natural language launches one configured agent (`CFCTL_AGENT`; default
`codex`, also `claude`, `cursor`, `gemini`). The agent turns intent into a
deterministic `cfctl resolve` match and governed commands — model output never
grants authority or mutates Cloudflare directly. Quote natural language: a
bare unknown token fails closed with a did-you-mean, so a typo is never an
agent launch. Browser and Computer Use are available only for cataloged
`governed_ui` capabilities, under the same account binding, redaction,
approval, and evidence rules.

## Evidence and state

Meaningful operations leave redacted, content-addressed local evidence, with
the evidence class distinguishing source config, live reads, plans, applies,
post-change verification, agent actions, and local proof. Artifact presence is
not verification.

`cfctl migrate v1` copies safe desired state and non-secret evidence into
content-addressed imports, skipping secret-shaped paths and never importing
credentials implicitly. Retained v1 data is quarantined under
[`compat/v1/`](compat/v1/README.md) as inert migration evidence; the live
catalog is managed under `CFCTL_HOME`.

## Development

Rust 1.97 is pinned. The authoritative source proof is `cargo xtask verify`;
it covers formatting, warnings-denied Clippy, all Rust tests, two complete edge
builds with artifact-drift rejection, the Bun bridge, dependency policy,
full-history secret scanning, source and governance contracts, and the Linux
musl cross-build. It needs pinned Bun, cargo-leptos, and worker-build tools,
`cargo-deny`, Gitleaks, Zig, `cargo-zigbuild`, and the Linux musl and WebAssembly
targets. The tracked pre-push gate runs this same local lane; no GitHub Actions
workflow or hosted CI service is required. See
[CONTRIBUTING.md](CONTRIBUTING.md) for setup, the pre-push gate, and the
assembly, signing, and publishing lanes.

Prebuilt release artifacts must not be published unless both macOS binaries carry one reviewed
Developer ID Application identity, hardened runtime, secure timestamps, and
accepted Apple notarization receipts. `SHA256SUMS` and the commit-bound
provenance must each carry a Sigstore bundle for the certificate identity and
OIDC issuer recorded independently in `SECURITY.md`. Reproducible
double-builds, SPDX SBOMs, and checksum verification remain part of the same
release contract; signatures do not replace them.

`cargo xtask assemble` remains an unsigned, local qualification lane. Its
outputs are not public release artifacts and the rendered installer refuses
them. Release installation guidance remains withheld until those independent
trust roots and the published artifact set have both been read back. A source
build is a separate local build and is not evidence that a published binary was
used.

`cfctl.com` site publication, publisher-domain verification, permanent
Cloudflare OAuth promotion, and release publication each require explicit
operator action and are never silently performed or claimed. Publishing the
site does not enable public OAuth.

After a governed site deployment, verify the named live origin with:

```bash
bun site/scripts/verify-live-site.mjs https://<exact-production-origin>
```

This checks public routes, security and cache headers, callback SSR privacy,
the live asset manifest, and immutable JS/Wasm/CSS delivery. It proves HTTP
behavior for that origin; the active Worker version and traffic allocation
still require the separate governed `cfctl` provider readback.

Source-only releases are labeled explicitly, contain no uploaded binary or
installer assets, and do not replace the GitHub latest binary release. They
allow publication and local installation from accepted source without Apple
signing credentials. Follow the source bootstrap in CONTRIBUTING.md; source
installation does not qualify a public prebuilt binary.
