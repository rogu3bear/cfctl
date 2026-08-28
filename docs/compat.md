# v1 compatibility boundary

v2 is a clean public CLI break. The tracked v1 shell/Python runtime was removed
after a hash-bound behavioral audit; it is not a shim, backend, or fallback.

See the [human audit](v1-parity.md) and
[machine-readable ledger](../compat/v1-parity-audit.json). Existing users can
run `cfctl migrate v1` from a v1 checkout to import safe desired state and
evidence. Credentials and secret-shaped content are never migrated.

This repository's own retained v1 state and static catalog are quarantined
under [`compat/v1/`](../compat/v1/README.md). They are evidence, not a second
public command surface. The live v2 catalog is the managed `CapabilityV1`
catalog under `CFCTL_HOME`.

The pre-release `wrangler_session` profile kind is accepted only as inert
metadata so affected profile stores remain inspectable. It cannot be selected
or used as a credential. `cfctl doctor --json` reports the exact metadata-only
logout command; removal does not touch the platform credential store. Create a
supported OAuth or API-token profile afterward.

## Command migration

Run `cfctl commands` for the complete v2 grammar and one-line purpose of every
deterministic path. For a Cloudflare operation, use `cfctl resolve "<intent>"`,
inspect the selected contract with `cfctl catalog show <capability-id>`, read
its lifecycle with `cfctl guide <capability-id>`, and invoke only the emitted
`cfctl call <capability-id>` path. That sequence covers native, dynamic API,
delegated CLI, governed UI, and blocked catalog entries without reviving v1
backend scripts.

Retired v1 command shapes deliberately have no shorthand aliases. They fail
closed with usage guidance instead of launching an agent or silently changing
meaning. `cfctl migrate v1` migrates supported non-secret state; it does not
translate or execute a v1 command.
