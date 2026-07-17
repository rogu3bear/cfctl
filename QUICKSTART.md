# cfctl v2 quickstart

## Build and install

Rust 1.93 or newer is pinned by `rust-toolchain.toml`.

```bash
./bootstrap.sh --check-only
./bootstrap.sh
# Intentional binary-only install; leaves managed agent integrations untouched.
./bootstrap.sh --skip-agent-sync
```

Bootstrap requires a tracked-clean checkout, runs the full verification lane,
installs with `cargo install --force`, proves the installed commit equals
`HEAD`, synchronizes only already-managed agent integrations unless skipped,
and runs both doctors. Confirm the exact running build after installation:

```bash
cfctl version --json
cfctl doctor --json
cfctl agents doctor --json
```

Or install directly from the checkout:

```bash
cargo install --path crates/cfctl-cli --locked
```

The Linux release installer requires Cosign, verifies the release's signed
checksum manifest against its exact Fulcio identity and issuer, and requires an
existing release tag:

```bash
curl -fsSL https://cfctl.io/install.sh | CFCTL_VERSION=v2.0.0 sh
```

## Discover Cloudflare

```bash
cfctl version --json
cfctl doctor
cfctl catalog sync
cfctl catalog coverage --json
cfctl catalog search "Worker secret"
cfctl docs changes
```

The catalog refreshes from Cloudflare's official OpenAPI schema, docs text feed, changelog, installed Wrangler help, and installed cloudflared help. A catalog older than 24 hours refreshes before use.

Reads with complete schemas can execute through the dynamic API adapter.
Generated writes remain discoverable but are blocked until their exact risk,
cost, entitlement, permission, verifier, and rollback/irreversibility contract
is implemented. Official product pricing references and OpenAPI plan
availability are attached when they match, but unbounded downstream usage
remains blocked. `catalog show` explains every missing field, and `catalog
coverage` separates pricing-reference and entitlement coverage from complete
executable mutation contracts.

For disposable tests, isolate all non-credential state explicitly:

```bash
CFCTL_HOME=/tmp/cfctl-proof cfctl doctor --json
```

`CFCTL_HOME` must be absolute. Credentials remain in Keychain on macOS or Secret Service on Linux.

## Authenticate

Simplest day-to-day lane — scoped API token from stdin, account pin required:

```bash
printf '%s' "$CLOUDFLARE_API_TOKEN" | \
  cfctl auth import-api-token --account <account-id> --stdin
cfctl auth status --json
```

Piping through a build wrapper such as the in-repo `./cfctl` shim can lose
stdin to `cargo`. When you invoke cfctl that way, hand it a mode-0600 file
instead — the token never rides stdin:

```bash
( umask 077; printf '%s' "$CLOUDFLARE_API_TOKEN" > token.tok )
cfctl auth import-api-token --account <account-id> --value-in token.tok
rm -f token.tok
```

OAuth is optional when you have a Cloudflare OAuth client (public cfctl OAuth
is not default until promoted):

```bash
cfctl auth login \
  --profile default \
  --client-id "$CFCTL_OAUTH_CLIENT_ID" \
  --account <account-id>
printf '%s\n' '<STATE CODE>' | cfctl auth login \
  --complete \
  --profile default \
  --client-id "$CFCTL_OAUTH_CLIENT_ID"
```

An emergency global key can be imported through stdin, or from a mode-0600 file
with `--value-in` (use the file form under `./cfctl`, whose cargo wrapper eats
stdin). It is never selected automatically:

```bash
printf '%s' "$CLOUDFLARE_API_KEY" | \
  cfctl auth import-global-key --profile emergency-global --email you@example.com --stdin

# or stdin-free:
( umask 077; printf '%s' "$CLOUDFLARE_API_KEY" > key.tok )
cfctl auth import-global-key --profile emergency-global --email you@example.com --value-in key.tok
rm -f key.tok
```

## Read and change

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
status and run `cfctl plans rectify <operation-id>`.

Credential-producing calls also require a new local sink:

```bash
cfctl call cloudflare-tunnel-get-a-cloudflare-tunnel-token \
  --selector account_id=<account-id> \
  --selector tunnel_id=<tunnel-id> \
  --value-out /tmp/tunnel-token
```

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

## Install agent discovery

```bash
cfctl agents install --all-detected
cfctl agents doctor
cfctl "inspect the current Worker routes for example.com"
```

Agents use deterministic commands underneath. A recursion marker prevents an agent from launching another agent through the bare-intent path. Model output never approves or directly mutates Cloudflare. Quote natural language — a bare single token that is not a known command fails closed with a usage error instead of launching an agent.
