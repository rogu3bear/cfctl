# Runtime Policy

This runtime is hardened around one public contract: `cfctl`.

## Landing Flow

Arriving agents should use this order:

```bash
cfctl doctor
cfctl surfaces
cfctl docs
cfctl standards audit
cfctl standards <surface>
cfctl explain <surface>
cfctl classify <surface> <operation>
cfctl guide <surface> <operation>
```

For unfamiliar or non-trivial writes:

```bash
cfctl guide <surface> <operation> ...
```

## Write Policy

- Mutation backends are backend-only by default.
- Public writes go through `cfctl apply ...`.
- Preview-required operations must run with `--plan` first.
- The reviewed preview emits an `operation_id`.
- The real mutation must repeat the command with `--ack-plan <operation-id>`.
- Use `cfctl previews` to inspect preview receipts and `cfctl previews purge-expired` to remove expired ones.
- Use `cfctl locks` to inspect write locks and `cfctl locks clear-stale` to remove only stale/orphaned locks.
- Destructive paths still require explicit confirmation such as `--confirm delete`.

## Secret Policy

- Runtime artifacts and backend artifacts are redacted by default.
- `cfctl token mint` does not print the token secret by default.
- For real token delivery, prefer:

```bash
cfctl token mint ... --value-out <secure-path>
```

Stdout reveal stays disabled unless runtime policy explicitly allows it.

## Backend Policy

- `scripts/cf_mutate_*`, `scripts/cf_api_apply.sh`, and `scripts/cf_token_mint.sh` are backend-only.
- Direct maintainer/debug use requires:

```bash
AUTH_PATH="$(cfctl admin authorize-backend --backend scripts/cf_api_apply.sh --reason 'maintainer debug' | jq -r '.result.authorization_path')"
CF_BACKEND_BYPASS_FILE="$AUTH_PATH" ./scripts/cf_api_apply.sh
```

- Read-only inventory scripts remain callable, but they are still backend surfaces rather than the public UX.

## Trust Checks

Use:

```bash
cfctl doctor
cfctl doctor --strict
cfctl doctor --repair-hints
cfctl audit trust
```

to verify:

- lane health
- backend-guard coverage
- artifact secret scan
- runtime policy shape
- preview receipt health
- lock health
- backend authorization health

`cfctl audit trust` is an alias for `cfctl doctor`.
