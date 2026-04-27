# Compatibility

This repo is migrating toward a `cfctl`-only public interface.

Current policy:
- `cfctl` is the only primary interface that should be taught to agents.
- existing `scripts/cf_*` entrypoints remain as compatibility shims/backends.
- mutation-capable backends are backend-only and reject direct invocation unless `cfctl` invoked them or you provide `CF_BACKEND_BYPASS_FILE=<authorization-path>` from `cfctl admin authorize-backend`.
- read-only inventory scripts can still be called directly, but they are not the preferred public UX.
- new features should land in `cfctl` first, not as new public scripts.

See [compat/script-entrypoints.json](compat/script-entrypoints.json) for a machine-readable map from legacy paths to `cfctl` replacements.
