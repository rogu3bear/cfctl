# cfctl v2 operator runbook

## Health and discovery

```bash
cfctl version --json
cfctl doctor --json
cfctl catalog sync --json
cfctl catalog coverage --json
cfctl docs changes --json
cfctl agents doctor --json
```

Require the PATH entry reported by both doctors to resolve to the running
executable. A doctor never launches a different PATH executable to inspect it;
invoke that binary directly with `cfctl version --json` if its self-reported
identity is needed. Missing or different PATH executables and
managed-instruction drift are unhealthy installation states.

If a command reports `catalog content hash mismatch`, do not edit the stored
hash. Run `cfctl catalog sync --json` to fetch a fresh official snapshot and
inspect `previous_catalog`. `discarded_invalid` means the corrupt current file
was replaced without overwriting the last valid previous snapshot; ordinary
catalog reads and plans remain fail-closed until that explicit repair succeeds.

Use `mutation_contract_gap_counts` to distinguish unknown risk, effect, cost,
verification, rollback, permissions, and entitlement debt. Counts overlap;
`capabilities_with_mutation_contract_gaps` counts affected operations once,
while `blocked_adapters_without_contract_gaps` identifies separate adapter or
workflow blockers. Search a stable gap name such as `verification_missing` or
its spaced form (`verification missing`) to list matching operations before
choosing a repair slice.

A blocked capability hit at execution time fails closed with error code
`CFCTL_CAPABILITY_BLOCKED`. The envelope carries the `capability_id`, the
`blocking_gaps` list, and a `next_step` that routes to
`cfctl guide <capability-id> --json`; follow the guide's `next_action` instead
of retrying the call or routing around cfctl.

Choosing a repair slice: read `mutation_contract_gap_counts` from
`cfctl catalog coverage --json`, pick one gap code, and list its operations
with `cfctl catalog search "<gap_code> <product>" --json`. Close the slice in
source (catalog classifier plus, when a new verification strategy is declared,
its support arm in `cfctl-core`), then prove it with before/after coverage
counts from `cfctl catalog sync` and `cfctl catalog coverage --json`.

Find and inspect an operation:

```bash
cfctl resolve "<natural-language intent>" --json
cfctl catalog search "<intent>" --json
cfctl catalog show <capability-id> --json
cfctl guide <capability-id> --json
```

`cfctl resolve` deterministically maps a goal to a capability and emits the exact
governed `call`/`approve`/`run` commands, failing closed with ranked candidates
when the match is ambiguous. Treat the guide as an executable safety contract,
not prose. Run `call_argv`
only when `contract_state` is `available`. When it is `blocked`, resolve every
named `blocking_gaps` entry through the supplied safe `next_action`; the
`post_resolution_call_argv` field is a template and is deliberately not an
execution recommendation. It is `null` when no safe future execution surface
exists. Commands are argv arrays so agents never have to guess shell quoting.

For a zone mutation with `check_entitlement` marked `live_read_required`, the
generated `next_action.argv` performs a Billing Read of the exact zone
subscription before it creates a plan. The plan binds that normalized receipt,
and execution rechecks it. Do not substitute account subscription output or
manually edit `observed_plan`; ambiguous, inactive, unavailable, and drifted
entitlements remain blocked.

For account-, global-, or user-scoped plan gates, `check_entitlement` remains
`blocked` when the official schema has no product-scoped subscription join key.
The generated next action explains the missing join and opens the matching
official plan documentation. An arbitrary active entry from
`GET /accounts/{account_id}/subscriptions` is not entitlement proof.

For an executable zone mutation, `select_account` is also
`live_read_required`. The exact call reads `GET /zones/{zone_id}` and requires
the returned zone and `account.id` to match the target and selected account.
That ownership receipt is re-read before plan consumption; do not infer
ownership from a profile label, workspace pin, or local IaC.

## Exit codes

Every invocation returns one of three exit codes. `0` is success. `1` is a
handled failure that renders a `ResultEnvelopeV2`; every failure envelope
carries a `next_step`. `2` is a clap usage error: the rejected arguments print
as raw clap output, and an envelope appears only under `--json`, with error
code `CFCTL_USAGE`.

## Authentication

Day-to-day auth is a scoped API token imported out-of-band. Pipe it through
stdin, or hand cfctl a mode-0600 file with `--value-in` when a build wrapper
(such as the in-repo `./cfctl` shim, which routes stdin through `cargo`) would
otherwise swallow stdin:

```bash
printf '%s' "$CLOUDFLARE_API_TOKEN" | \
  cfctl auth import-api-token --account <account-id> --stdin --json

# or, stdin-free (survives ./cfctl):
( umask 077; printf '%s' "$CLOUDFLARE_API_TOKEN" > token.tok )
cfctl auth import-api-token --account <account-id> --value-in token.tok --json
rm -f token.tok
```

OAuth login (optional) uses PKCE and an explicit client id until public cfctl
OAuth is promoted:

```bash
cfctl auth login --profile default --client-id <client-id> \
  --account <account-id> --json
```

Open the returned authorization URL, then pipe the callback's one-time
`STATE CODE` value into the same command with `--complete`. Use `auth status`,
`profiles`, `use`, and `logout` for profile lifecycle. Import an emergency
global key only through stdin; cfctl never selects it silently.

If `doctor` reports an unsupported `wrangler_session` profile, it is inert
metadata left by a pre-release experiment. `auth profiles` and `doctor` remain
readable, but `auth status`, `auth use`, planning, and execution reject that
profile. Remove it with the exact `remove_argv` reported by `doctor`, then
create a supported OAuth or API-token profile. Legacy-profile removal does not
read, delete, or reinterpret any credential-store entry; cfctl does not revive
Wrangler authentication as an API or delegated-CLI credential lane.

## Workspace boundaries

```bash
cfctl workspace add /absolute/root --account <account-id> --json
cfctl workspace discover --json
cfctl workspace graph --json
cfctl workspace audit --json
```

Only registered roots are scanned. Nested `fixtures`, `__fixtures__`,
`testdata`, `test-data`, and `test_data` directories are excluded from a
broader root; register a fixture directory directly to opt it into discovery.
Fix account ambiguity or dirty overlap before planning writes.

## Reads

```bash
cfctl call <capability-id> \
  --selector account_id=<account-id> \
  --query per_page=100 --json
```

The typed transport validates selectors and bodies against the pinned schema,
paginates, backs off on rate limits, uses conditionals when supplied, and emits
structured Cloudflare errors.

## Writes

`call` creates a plan for a mutating capability. Review it, then:

```bash
cfctl plans show <operation-id> --json
cfctl plans approve <operation-id> --yes --json
cfctl plans run <operation-id> --json
cfctl plans status <operation-id> --json
```

Use `--max-cost CURRENCY:AMOUNT` for paid plans. Use `plans resume` only for a
draft or approved plan; consumed/running plans are deliberately non-replayable.
Use `plans rectify` to inspect compensation and verification steps after an
uncertain or unsupported result.

Secret outputs require `--value-out /new/secure/path`; cfctl refuses an
existing destination.

Mint an account token only through the dedicated key workflow:

```bash
cfctl keys permissions --account <account-id> --json
cfctl keys mint --name <name> --permission <reviewed-group-id> \
  --account <account-id> --ttl-hours <hours> \
  --value-out /new/secure/path --json
```

Mint planning repeats the live permission inventory and binds the exact group
metadata and account-only resource policy. Running the approved plan repeats
that inventory read before consumption; drift requires a new plan. Do not use
generic `call` for account API-token creation.

Mint a user-owned token for one explicit account with the parallel governed
workflow:

```bash
cfctl keys permissions --user --account <account-id> --json
cfctl keys mint --user --name <name> --permission <reviewed-group-id> \
  --account <account-id> --ttl-hours <hours> \
  --value-out /new/secure/path --json
```

The `--user` flag changes token ownership and the permission-inventory
endpoint, not the policy scope: every selected group must declare account scope
and the policy remains pinned to the one `--account` value. Use the same flag
for `keys rotate` and `keys revoke`; those plans select the user token endpoint
while preserving the explicit account authority context.

### Standing authority

Recurring token-lifecycle work can run unattended under a bounded standing
policy instead of per-operation approval. Draft one from a fresh permission
inventory, then inspect what already exists:

```bash
cfctl keys policy create --account <account-id> --name-prefix <prefix> \
  --permission <reviewed-group-id> --max-child-ttl-hours <hours> \
  --max-runs-per-day <count> --json
cfctl keys policy list --json
```

`keys policy create` drafts a hash-bound standing authority (pinned account,
name prefix, permission-group allowlist, max child TTL, and per-day run
ceiling); it is inert until activated. `keys policy list` inspects existing
authorities and reports effective status, remaining budget, lineage, and next
action. Activate one reviewed authority ID only with explicit approval, and
close it immediately when the work is done:

```bash
cfctl keys policy approve <authority-id> --yes --json
cfctl keys policy revoke <authority-id> --json
```

Standing approval moves authority to that bounded policy; it is not blanket
mutation authority, and external sends and spend are never standing-authorized.
Load `cfctl guide --topic standing-authority --json` before drafting one.

Create an Access service token through its separate exact account or zone
lifecycle. The input is intentionally limited to `name` and optional
`duration`; version and grace-period fields belong to rotation, not initial
creation. The new sink is JSON with exactly `client_id` and `client_secret`.
For an account-scoped token:

```bash
printf '%s' '{"name":"deployment automation"}' | \
  cfctl call access-service-tokens-create-a-service-token \
    --selector account_id=<account-id> --body-stdin \
    --value-out /new/secure/access-service-token.json --json
```

For a zone-scoped token, use the distinct operation and selector rather than
retargeting the account operation:

```bash
printf '%s' '{"name":"zone deployment automation"}' | \
  cfctl call zone-level-access-service-tokens-create-a-service-token \
    --selector zone_id=<zone-id> --body-stdin \
    --value-out /new/secure/zone-access-service-token.json --json
```

Review, approve, and run the returned operation ID normally. A successful run
requires the mode-0600 sink plus an exact readback of the returned service-token
ID, name, and duration within the same account or zone scope. `plans rectify`
may create a separate reviewed exact-scope delete plan; it never deletes
automatically. Keep
`access-service-tokens-rotate-a-service-token` blocked while its official
operation schema omits the required permission lane.

Rename a service token or choose a new duration without entering the rotation
lane:

```bash
printf '%s' '{"name":"deployment automation","duration":"17520h"}' | \
  cfctl call access-service-tokens-update-a-service-token \
    --selector account_id=<account-id> \
    --selector service_token_id=<service-token-id> --body-stdin --json
```

For a zone-scoped token, use the distinct zone operation and selector:

```bash
printf '%s' '{"name":"zone deployment automation","duration":"17520h"}' | \
  cfctl call zone-level-access-service-tokens-update-a-service-token \
    --selector zone_id=<zone-id> \
    --selector service_token_id=<service-token-id> --body-stdin --json
```

cfctl reads the exact token back and compares every planned field. It rejects
`client_secret_version` and `previous_client_secret_expires_at`: Cloudflare
documents those as secret-rotation and old-secret grace controls. A duration
update resets expiration, so restoring the exact prior expiration is not a
valid rollback claim; correction requires a separate reviewed update plan.

Extend an existing service token by the one-year interval Cloudflare documents:

```bash
cfctl call access-service-tokens-refresh-a-service-token \
  --selector account_id=<account-id> \
  --selector service_token_id=<service-token-id> --json
```

The call is body-free and irreversible. After apply, cfctl requires HTTP 200,
the exact planned token identity, a valid future `expires_at`, and an immediate
detail readback with the same identity and expiration. It never presents the
extension as restorable; a lifetime correction is a separate reviewed plan.

Turnstile secret rotation requires an explicit cutover choice. `false` keeps
the prior secret valid for two hours and prevents another rotation during that
window; `true` invalidates it immediately. In both cases the new secret is
written only to a new sink:

```bash
printf '%s' '{"invalidate_immediately":false}' | \
  cfctl call accounts-turnstile-widget-rotate-secret \
    --selector account_id=<account-id> --selector sitekey=<sitekey> \
    --body-stdin --value-out /new/secure/path --json
```

Rotate an OAuth client secret as a staged two-secret cutover. Planning and
execution both require the exact client to report that no overlap secret exists;
the new value is sink-only:

```bash
cfctl call oauth-clients-rotate-secret \
  --selector account_id=<account-id> \
  --selector oauth_client_id=<oauth-client-id> \
  --value-out /new/secure/oauth-client-secret --json
```

Update and verify every dependent while the old value remains valid. Only then
create, review, approve, and run the separate irreversible deletion plan:

```bash
cfctl call oauth-clients-delete-rotated-secret \
  --selector account_id=<account-id> \
  --selector oauth_client_id=<oauth-client-id> --json
```

The first phase must read back `has_rotated_secret=true`; the second requires
that state before planning and must read back `false`. A second rotation, a
delete from one-secret state, target drift, and a stale approval all fail before
the mutation boundary.

## Agent entry

```bash
cfctl agents install --all-detected --json
cfctl agents doctor --json
cfctl "<natural-language Cloudflare request>"
```

Natural language launches one configured local agent. The agent must translate
intent to deterministic commands; it cannot approve or directly mutate state.
Quote natural language: a bare single token that is not a known command fails
closed with a usage error instead of launching an agent.

## Local proof

```bash
cargo xtask verify
```

Do not report completion without the applicable source-config, live-read,
preview, apply, and post-change verification evidence.
