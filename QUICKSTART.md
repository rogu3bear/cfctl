# cfctl v2 quickstart

## Build and install

Rust 1.97 or newer is pinned by `rust-toolchain.toml`. The guided bootstrap
requires a checkout clean of tracked and untracked non-ignored files, runs the
full verification lane, installs with `cargo install --force`, proves the
installed commit equals `HEAD`,
synchronizes only already-managed agent integrations (`--skip-agent-sync`
leaves them untouched), and runs both doctors:

```bash
./bootstrap.sh --check-only
./bootstrap.sh
# or, skipping that lane:
cargo install --path crates/cfctl-cli --locked
```

Prebuilt binaries ship from the GitHub release. Releases are unsigned by
operator decision: integrity is checksum-based, so verify every download
against the release's `SHA256SUMS` (each binary is also reproducible from the
tagged source and carries an SPDX SBOM).

```bash
curl -fsSLO https://github.com/rogu3bear/cfctl/releases/download/v1.2.1/cfctl-aarch64-apple-darwin
curl -fsSLO https://github.com/rogu3bear/cfctl/releases/download/v1.2.1/SHA256SUMS
shasum -a 256 --check --ignore-missing SHA256SUMS
install -m 0755 cfctl-aarch64-apple-darwin ~/.local/bin/cfctl
```

On macOS the release's Homebrew formula (`cfctl.rb`) pins the same checksums:
`brew install --formula ./cfctl.rb`. The identity-verifying Linux installer is
not shipped while releases are unsigned; use the direct download + checksum
path with the `-unknown-linux-musl` binary for your architecture.

Confirm the exact running build after any install path:

```bash
cfctl version --json
cfctl doctor --json
cfctl agents doctor --json
```

## Discover Cloudflare

```bash
cfctl catalog sync
cfctl catalog coverage --json
cfctl resolve "telemetry overview" --json
cfctl call workflow.telemetry.audit-account --json
cfctl resolve "rotate a worker secret"
cfctl catalog search "Worker secret"
cfctl docs changes
```

The catalog refreshes from Cloudflare's official OpenAPI schema, docs text
feed, changelog, and installed Wrangler/cloudflared help; a catalog older than
24 hours refreshes before use. Reads with complete schemas execute through the
dynamic API adapter; generated writes remain discoverable but blocked until
their full safety contract is implemented, and `catalog show` explains every
missing field.

For disposable tests, isolate all non-credential state with an absolute
`CFCTL_HOME` (for example `CFCTL_HOME=/tmp/cfctl-proof cfctl doctor --json`).
Credentials go to the platform keyring first — Keychain on macOS or Secret
Service on Linux — and fail down to a governed mode-0600 file store under
cfctl's data directory (`auth/secrets`) when that keyring is unavailable;
`cfctl doctor` reports the active backend.

## Authenticate

Simplest day-to-day lane — scoped API token from stdin, account pin required:

```bash
printf '%s' "$CLOUDFLARE_API_TOKEN" | \
  cfctl auth import-api-token --account <account-id> --stdin
cfctl auth status --json
```

A build wrapper such as the in-repo `./cfctl` shim can lose stdin to `cargo`;
when you invoke cfctl that way, hand it a new mode-0600 file with `--value-in`
instead so the token never rides stdin. Optional OAuth login (explicit
`--client-id`; public cfctl OAuth is not default until promoted) and the
never-implicit emergency global key (`cfctl auth import-global-key`) are
covered in the README.

## First governed write

```bash
cfctl call zones-get --query name=example.com --json
cfctl guide dns-records-for-a-zone-create-dns-record
cfctl call dns-records-for-a-zone-create-dns-record \
  --selector zone_id=<zone-id> \
  --body-json '{"type":"TXT","name":"_example","content":"hello"}'
```

The write returns a plan and exact operation ID. If approval is required:

```bash
cfctl plans approve <operation-id> --yes
cfctl plans run <operation-id>
cfctl plans status <operation-id>
```

The plan's hash-chained journal makes crash position explicit. If cfctl may
have crossed the Cloudflare boundary, do not replay the operation; inspect the
status and run `cfctl plans rectify <operation-id>`. Credential-producing
calls also require a new mode-0600 sink via `--value-out`.

<!-- BEGIN CFCTL GENERATED: standing-authority-guide -->
## Standing authority lifecycle

Standing authority is the bounded token-lifecycle exception: one explicitly approved local policy may admit matching token mints and lineage-bound revocations without per-operation approval.

**Will this mutate Cloudflare now?** Permission reads and policy create, list, approve, and revoke are local or read-only. A matching `keys mint --under-policy` or lineage-bound token revoke may cross the Cloudflare boundary after durable admission.

**What grants authority?** Only `cfctl keys policy approve <authority-id> --yes` activates the exact reviewed policy. Its account, capabilities, permission allowlist, token-name prefix, child TTL, rate budget, expiry, and content hash remain binding.

**What is persisted?** cfctl persists the schema-v1 authority document, approval, run reservations, plan journals, reconciled minted-token lineage, and redacted evidence. The one-time token value goes only to the requested mode-0600 sink.

**What happens after a failure or crash?** Revocation blocks runs not yet durably admitted; an already durably admitted run may finish. A validated boundary receipt is reconciled into lineage even after sink or verification failure, and later recovery never replays the Cloudflare mutation.

**What should I do next?** Read the fresh account permission inventory, then create a narrow policy using exact permission IDs or unambiguous exact names.

### Lifecycle

1. **Read permissions** (`read`) — Fetch one fresh account-owned permission inventory. Durable state: live permission receipt
2. **Create policy** (`none`) — Resolve the allowlist and bind every standing-authority limit. Durable state: pending StandingAuthorityV1
3. **Approve policy** (`none`) — Review the exact authority ID and activate it with explicit `--yes`. Durable state: approved authority content hash
4. **Admit child** (`none`) — Recheck the child subset and complete allowlist, reserve the run under lock, and consume the child plan. Durable state: run reservation and plan consumption
5. **Execute child** (`write`) — Release the authority lock, then mint or revoke exactly within the approved bounds. Durable state: boundary attempt and response
6. **Sink and reconcile** (`none`) — Write the one-time secret sink and reconcile any created token ID from the validated response. Durable state: secret-sink receipt and minted-token lineage
7. **Verify** (`read`) — Verify the remote token identity and status or require rectification without replay. Durable state: verification receipt and final plan status
8. **Revoke policy** (`none`) — Close future admission immediately; already minted child tokens remain separate resources. Durable state: monotonic revoked authority status

### Commands

```bash
cfctl keys permissions --account <account-id> --json
cfctl keys policy create --account <account-id> --name-prefix <token-prefix> --permission <permission-group-id> --max-child-ttl-hours 24 --max-runs-per-day 4 --expires-days 30 --json
cfctl keys policy list --json
cfctl keys policy approve <authority-id> --yes --json
cfctl keys mint --name <token-name> --permission <permission-group-id> --account <account-id> --ttl-hours 12 --value-out <new-mode-0600-path> --under-policy <authority-id> --json
cfctl keys policy list --json
cfctl keys policy revoke <authority-id> --json
```
<!-- END CFCTL GENERATED: standing-authority-guide -->

## Unattended analytics-profile renewal

Create and separately approve one account-and-zone-bounded authority using the
minter profile. The child allowlist must contain exactly `Account Analytics
Read` and zone `Analytics Read`; two standing runs per completed renewal cover
one mint and one lineage-bound old-child revoke.

```bash
cfctl keys policy create \
  --profile minter \
  --account <account-id> \
  --zone <zone-id> \
  --name-prefix jkca-public-activity- \
  --permission "Account Analytics Read" \
  --permission "Analytics Read" \
  --max-child-ttl-hours 168 \
  --max-runs-per-day 4 \
  --expires-days 365 \
  --json

cfctl keys policy approve <authority-id> --yes --json

cfctl keys renew-analytics-profile \
  --profile jkca-public-activity-read \
  --minter-profile minter \
  --account <account-id> \
  --zone <zone-id> \
  --hostname jkca.me \
  --permission "Account Analytics Read" \
  --permission "Analytics Read" \
  --ttl-hours 168 \
  --renew-before-hours 24 \
  --name-prefix jkca-public-activity- \
  --under-policy <authority-id> \
  --json
```

The first run for a pre-existing profile also needs
`--current-token-id <active-child-id> --force`. That child predates the new
authority, so cfctl activates and verifies the fresh child but returns exit 1
with a one-time revoke operation ID. Approve and run that exact operation.
Until its not-found verification is durable, every hourly renewal check keeps
returning a nonzero `CFCTL_ANALYTICS_ROTATION_OLD_REVOKE_PENDING` signal.
Later renewals are fully unattended because both children are lineage-bound.

The fresh secret exists only in cfctl's private sink and immutable credential
slot. The publisher profile switches slots through one atomic metadata write.
Before that switch and again afterward, cfctl requires successful account RUM
settings, zone analytics settings, and exact-hostname RUM reads. Healthy
hourly checks repeat the same three reads, so inaccessible credentials or
analytics contract drift cannot be reported as `healthy_not_due`. Any failure
preserves or restores the prior profile, revokes the fresh child when safely
lineage-bound, emits redacted evidence, and exits nonzero.

## Install agent discovery

```bash
cfctl agents install --all-detected
cfctl agents doctor
cfctl "inspect the current Worker routes for example.com"
```

Agents use deterministic commands underneath; a recursion marker prevents an
agent from launching another agent, and model output never approves or
directly mutates Cloudflare. Quote natural language — a bare single token that
is not a known command fails closed with a usage error, never an agent launch.
