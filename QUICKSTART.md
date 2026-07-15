# cfctl v2 quickstart

## Build and install

Rust 1.93 or newer is pinned by `rust-toolchain.toml`.

```bash
./bootstrap.sh --check-only
./bootstrap.sh
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

The public cfctl OAuth application is not active until cfctl.io ownership is verified and the permanent Cloudflare promotion is approved. Until then, use your own Cloudflare OAuth client:

```bash
cfctl auth login \
  --profile default \
  --client-id "$CFCTL_OAUTH_CLIENT_ID" \
  --scope <scope-id> \
  --account <account-id>
```

Open the returned URL. Pipe the callback's `STATE CODE` value into:

```bash
printf '%s\n' '<STATE CODE>' | cfctl auth login \
  --complete \
  --profile default \
  --client-id "$CFCTL_OAUTH_CLIENT_ID"
```

An emergency global key can be imported through stdin. It is never selected automatically:

```bash
printf '%s' "$CLOUDFLARE_API_KEY" | \
  cfctl auth import-global-key --profile emergency-global --email you@example.com --stdin
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

## Install agent discovery

```bash
cfctl agents install --all-detected
cfctl agents doctor
cfctl "inspect the current Worker routes for example.com"
```

Agents use deterministic commands underneath. A recursion marker prevents an agent from launching another agent through the bare-intent path. Model output never approves or directly mutates Cloudflare.
