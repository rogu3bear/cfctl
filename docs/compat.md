# v1 compatibility boundary

v2 is a clean public CLI break. The tracked v1 shell/Python runtime was removed
after a hash-bound behavioral audit; it is not a shim, backend, or fallback.

See the [human audit](v1-parity.md) and
[machine-readable ledger](../compat/v1-parity-audit.json). Existing users can
run `cfctl migrate v1` from a v1 checkout to import safe desired state and
evidence. Credentials and secret-shaped content are never migrated.

The pre-release `wrangler_session` profile kind is accepted only as inert
metadata so affected profile stores remain inspectable. It cannot be selected
or used as a credential. `cfctl doctor --json` reports the exact metadata-only
logout command; removal does not touch the platform credential store. Create a
supported OAuth or API-token profile afterward.
