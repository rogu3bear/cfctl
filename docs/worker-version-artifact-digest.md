# Immutable Worker module digest read

`worker-version-artifact-digest` is a native, read-only projection of Cloudflare's
version-specific JSON API. Its consumer is Maildesk release qualification.
Discover it through `cfctl catalog show worker-version-artifact-digest --json`
and load `cfctl guide worker-version-artifact-digest --json` before use.

Bind the profile, account, Worker name or ID, and one full canonical version
UUID. Prefixes and `latest` are rejected before a provider request. The executor
forces `include=modules`; callers may omit that query parameter. It admits at
most 256 modules, 32 MiB decoded module bytes, and a 64 MiB response. Missing
modules or main entrypoint, version mismatch, duplicate or unsafe module names,
noncanonical base64, and exceeded bounds fail closed. Rejections return a fixed
reason code so an operator can distinguish a missing module response from a
version, encoding, name, or size failure without retaining provider text.

Wrangler module names may have one `./` prefix. The receipt preserves it exactly;
traversal, repeated prefixes, and aliases such as `x.wasm` plus `./x.wasm` are rejected.

Raw module content, sourcemaps, variables, bindings, and asset JWTs are discarded
inside the executor before evidence is written. The response contains the exact
version ID and a sorted manifest of module name, MIME type, byte count and
SHA-256, plus a hash of that version-1 JSON manifest. `--out` cannot export raw
module bytes through this capability. The existing generic API remains separate.

This read proves module content for the named immutable version. A release
consumer must separately prove that version is active and compare the module
manifest to the intended upload outputs. Deployment annotations alone cannot
provide either byte comparison. Static asset bytes are explicitly unqualified;
applications with assets require their own asset-content join.

The owning upstream endpoint is documented at
https://developers.cloudflare.com/api/typescript/resources/workers/subresources/beta/subresources/workers/subresources/versions/methods/get/.

This capability can be retired only when another governed body-free contract
preserves the same immutable version binding, completeness limits, and module
comparison without retaining source bytes.
