# Frozen Worker artifact upload

`wrangler.versions-upload` accepts the optional query control
`artifact_mode=frozen-artifact`. It uploads an already-built JavaScript Worker
and its declared assets. Omitting the control preserves ordinary Wrangler
upload behavior, including the configured custom build command.

Use `cfctl guide wrangler.versions-upload --json` to inspect the cataloged
controls. Supply the existing absolute canonical `config`, exact Worker `name`,
and release `message` controls together with `artifact_mode`. The message keeps
the existing form `source=<full Git SHA> artifact-sha256=<artifact-set SHA-256>`.
`cfctl call` creates the governed plan; approval and execution retain their
existing exact-operation lifecycle. The mode is cfctl policy and is consumed
before constructing Wrangler arguments.

The plan's `adapter.worker_deployment` target retains the source commit and
canonical config identity. Its versioned `frozen_artifact` companion contains
the complete sorted file manifest, directory membership, existing artifact-set
digest, projected config digest, selected module names/types/hashes, source-map
transport identities, and Wrangler executable/interpreter/dependency closure.
Source paths must be unambiguous UTF-8 names; symlinks and ancestor aliases are
rejected. File reads use directory-relative descriptors with no-follow semantics.

At execution, cfctl captures the admitted artifact into a private temporary
directory. The config projection preserves provider fields such as bindings,
routes, compatibility, asset options, and cron settings. It rewrites file paths
to that staged manifest, makes the module root explicit, enables `no_bundle`,
and removes the custom `build.command`. The original config and artifact are
never edited. Final checks reject changed source/config/artifact bytes or a
changed Wrangler producer before starting the credential-bearing process.
The temporary config, cache, diagnostics, and artifact copies share the
subprocess lifetime. Raw Wrangler output is not retained; the public receipt
contains hashes and a canonical uploaded-version identity.

This first contract requires an explicit already-built `.js`, `.mjs`, or `.cjs`
main module. It does not admit entry overrides, named environments, aliases,
TypeScript config discovery, Workers Sites, arbitrary extra flags, or unknown
config fields. File-backed bindings and module imports must remain inside the
manifest. Module rules retain their configured ordering and fallthrough;
supported types are ESModule, CommonJS, CompiledWasm, Text, and Data. Paths use
the bounded `*`/`**` glob grammar with literal non-star characters. Referenced
source maps must be valid maps with embedded source content for declared
sources; indexed maps and external map sections are rejected. Configuration or
file mechanisms outside this contract require an explicit implementation and
new qualification, rather than ambient discovery at upload time.

An uploaded version remains inert until separately promoted. Preserving routes
and cron in the config projection does not claim that version upload activated
those non-versioned settings. Upload-message verification, live version-module
digest readback, asset delivery, and active traffic remain distinct evidence.

The real-tool qualification fixtures execute Wrangler under OS network denial
with `--dry-run`; the custom build sentinel must never run in frozen mode and
must run in the ordinary control. These local tests do not perform or qualify a
Cloudflare deployment.
