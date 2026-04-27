# Compatibility

This directory documents the transitional contract while the repo moves from a flat script estate to a `cfctl`-first runtime.

- Public contract: `./cfctl`
- Compatibility contract: existing `scripts/cf_*` entrypoints continue to run
- Migration policy: keep old paths working, but stop teaching them as the primary interface

Machine-readable mappings live in [script-entrypoints.json](compat/script-entrypoints.json).
