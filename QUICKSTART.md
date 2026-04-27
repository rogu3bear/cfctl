# cfctl Quickstart

This walks you from "just cloned" to "first verified read against your Cloudflare account."

## 1. Install dependencies

`cfctl` is bash-first. You need:

| Tool | Required | Used for |
|---|---|---|
| `bash` (>= 4) | yes | runtime |
| `jq` | yes | parsing every API response and catalog file |
| `curl` | yes | direct API calls |
| `python3` | yes (for standards audit) | `cfctl standards audit` workspace scan |
| `wrangler` | optional | `cfctl wrangler ...` |
| `cloudflared` | optional | `cfctl cloudflared ...` and tunnel surfaces |

macOS:

```bash
brew install jq
# wrangler comes from npm/bun; cloudflared from brew or the Cloudflare download
```

Linux:

```bash
sudo apt install jq curl python3
# install wrangler / cloudflared per Cloudflare's official docs
```

## 2. Clone and put `cfctl` on your PATH

```bash
git clone https://github.com/rogu3bear/cfctl.git
cd cfctl
mkdir -p ~/bin
ln -s "$(pwd)/cfctl" ~/bin/cfctl
# make sure ~/bin is in your shell's PATH; otherwise use ./cfctl from the repo
```

You can also invoke `./cfctl` directly from inside the repo without the symlink — the runtime resolves its own root.

## 3. Set up credentials

`cfctl` reads credentials from `~/dev/.env` by default (this is configurable; the loader is in [scripts/lib/cloudflare.sh](scripts/lib/cloudflare.sh)). The minimum:

```env
CF_DEV_TOKEN=<your scoped Cloudflare API token>
CLOUDFLARE_ACCOUNT_ID=<your account id>
```

Get a token at <https://dash.cloudflare.com/profile/api-tokens>. The `dev` lane wants an API token. The optional `global` lane wants the global API key plus your Cloudflare email and is reserved for emergency wider-scope operations.

A repo-local `.env.example` and `.env.local.example` document every supported variable.

## 4. Run doctor

```bash
cfctl doctor
```

This checks: tooling presence, env loading, both auth lanes, account pin, runtime directories, and prints `repair-hints` if anything is degraded. Resolve any red items before going further.

## 5. First reads

```bash
cfctl surfaces                          # what cfctl knows how to operate
cfctl docs                              # compact official Cloudflare doc bank
cfctl list zone                         # zones in your pinned account
cfctl get zone --name example.com       # one zone (use one of yours)
cfctl explain dns.record                # surface contract, selectors, operations
```

## 6. First plan-then-apply (DNS as the canonical example)

```bash
# Plan only — emits an operation_id and a preview artifact under var/inventory/.
cfctl apply dns.record upsert \
  --zone example.com \
  --name _ops-smoke.example.com \
  --type TXT \
  --content hello-world \
  --ttl 120 \
  --plan

# Inspect the preview artifact, then ack to apply.
cfctl apply dns.record upsert \
  --zone example.com \
  --name _ops-smoke.example.com \
  --type TXT \
  --content hello-world \
  --ttl 120 \
  --ack-plan <operation_id>

# Verify the result.
cfctl get dns.record --zone example.com --name _ops-smoke.example.com --type TXT
```

If `cfctl can dns.record upsert ... --all-lanes` says the `dev` lane lacks the permission, switch lanes for that single command:

```bash
CF_TOKEN_LANE=global cfctl apply dns.record upsert ... --plan
```

## 7. Mint a short-lived scoped token

```bash
cfctl token permission-groups --name "DNS"

cfctl token mint \
  --name dns-editor-$(date +%Y%m%d) \
  --permission "DNS Write" \
  --zone example.com \
  --ttl-hours 24 \
  --plan

cfctl token mint \
  --name dns-editor-$(date +%Y%m%d) \
  --permission "DNS Write" \
  --zone example.com \
  --ttl-hours 24 \
  --ack-plan <operation_id> \
  --value-out /tmp/dns-editor.token
```

`--value-out` is required for the secret to leave the runtime — stdout reveal is policy-disabled by default. The path must be absolute, outside the repo, and not under `var/`.

## 8. Where to go next

- [README.md](README.md) — public contract and architecture overview
- [AGENTS.md](AGENTS.md) — operational landing for autonomous agents
- [docs/runbooks/cfctl.md](docs/runbooks/cfctl.md) — full verb reference
- [docs/capabilities.md](docs/capabilities.md) — generated capability table
- [docs/state.md](docs/state.md) — desired-state model

## Troubleshooting

| Symptom | First thing to check |
|---|---|
| `cfctl doctor` reports tool missing | `which jq curl python3` |
| `auth_lane` is red | `~/dev/.env` exists and has `CF_DEV_TOKEN` set; `CLOUDFLARE_ACCOUNT_ID` is the right account |
| `unsupported_surface` | `cfctl surfaces` for the canonical list; surface names are namespaced (e.g. `dns.record`, not `dns_record`) |
| Preview gate keeps blocking writes | Run with `--plan`, capture the `operation_id`, then rerun with `--ack-plan <operation_id>` |
| Lock errors | `cfctl locks` to inspect, `cfctl locks clear-stale` if the lock is owned by a dead process |
| Stuck preview | `cfctl previews` to inspect, `cfctl previews purge-expired` |
