# Contributing to cfctl

`cfctl` is a strict, catalog-driven Cloudflare control plane. A change is ready
only when its public contract, deterministic behavior, safety metadata, tests,
documentation, and evidence model agree.

## Ground rules

- `cfctl` is the only public interface. Do not reintroduce the archived v1
  shell runtime, expose flat backend scripts, hand-roll Cloudflare auth, or add
  a Cloudflare API MCP dependency.
- Search the catalog before adding behavior. New writes remain blocked until
  risk, effect, cost, permission, entitlement, verification, and rollback or
  explicit irreversibility are known.
- Classify capability authority separately from its adapter. Reusable
  Cloudflare behavior is `provider_generic`; cfctl's own public identity is
  `cfctl_product`. Do not compile a customer or application repository,
  account, database, migration, or deployment policy into either class. New
  `legacy_embedded` entries are prohibited; workspace-owned behavior must wait
  for the typed operation-pack loader and remain in its owning repository.
- Reads are not plans, plans are not applies, and apply artifacts are not
  post-change verification. Keep those evidence classes distinct.
- All new mutations use the one-use canonical `PlanV2` lifecycle. The stored
  `PlanV1` projection is compatibility data, not execution authority. Never
  weaken approval, account/target binding, catalog hashes, drift checks, locks,
  journals, verification, or rectification to make a capability executable.
- Secret inputs come from stdin or the platform secret store. Secret outputs
  require `--value-out`; values never belong in arguments, stdout, plans,
  logs, fixtures, or repository files.
- Workspace discovery stays inside explicitly registered roots. Preserve
  unrelated dirty work and report exact local diffs.

## Dependency policy

`cfctl` holds production Cloudflare credentials and authorizes production
mutations. For a tool with that blast radius, "up to date" is not the goal —
"the trust boundary is provably intact on every target it ships to" is. Every
dependency is both behavior-change surface and attack surface, so upgrades are
governed by risk, not recency.

- **Security-layer dependencies** — anything in the credential, crypto, or TLS
  path (`keyring*`, `*secret-service*`, `rustls`/`*-tls`, `sha2`, `oauth2`,
  `reqwest`, and the crates they pull into `cfctl-auth`) — upgrade **in
  isolation, one per change**, never bundled with unrelated maintenance. Each
  such change is reviewed on its own, must pass the `verify` Linux cross-build,
  and, when it alters credential storage or retrieval, is not considered shipped
  until its behavior is verified on a real Linux Secret Service host — the macOS
  proof lane cannot exercise that path. Currency alone is never sufficient
  justification; name the concrete driver (CVE, required feature, upstream drop).
- **Leaf and maintenance dependencies** — everything else — may be upgraded in
  routine batches, gated by `cargo xtask verify` (which now includes the Linux
  cross-build). A blanket "make it current" sweep is allowed here and only here.

The failure this policy prevents is a credential-layer rewrite riding into a
release on the confidence earned by a pile of harmless leaf bumps. Keep the two
lanes separate so a reviewer can see the risky change alone.

## Development setup

Rust 1.97 is pinned by the repository. The local proof lane needs `cargo-deny`,
Gitleaks, Bun 1.3.14, cargo-leptos 0.3.5, worker-build 0.7.5, and the
`wasm32-unknown-unknown` target. Because `cargo xtask verify` also cross-builds
the Linux ship target, it needs `zig`, `cargo-zigbuild`, and the
`x86_64-unknown-linux-musl` Rust target. `verify` fails closed when either the
site or cross-build toolchain is absent rather than skipping that proof.
Install them, then orient through the public CLI:

```bash
./bootstrap.sh
cfctl version --json
cfctl doctor
cfctl catalog sync
cfctl catalog coverage
cfctl workspace discover
cfctl workspace audit
cargo xtask verify
```

Bootstrap requires a checkout clean of tracked and untracked non-ignored files,
proves the installed binary is the exact `HEAD` commit, synchronizes only
managed agent integrations, and runs both doctors. It also reports the selected
runtime's evidence-key status without changing credentials. An unresolved status
remains visible but does not invalidate an offline installation; inspect
`cfctl auth evidence-key status --json` before governed operations. Use
`--check-only` for source proof or `--skip-agent-sync` for an intentional
binary-only install.

Authentication is optional for offline development. Use `cfctl auth login` or
an explicitly scoped token profile when live-read proof is required; never
create a repository `.env` with Cloudflare credentials.

### Local proof and pre-push gate

`cargo xtask verify` is the authoritative source proof. It runs formatting,
warnings-denied workspace Clippy, all workspace tests, the Cloudflare request
contract, site formatting/Clippy/tests, two complete edge builds to reject
nondeterminism, the Bun bridge proof, dependency policy, full-history secret
scanning, source/governance contracts, and the Linux musl cross-build. The
repository does not require GitHub Actions or another hosted CI service.

`.githooks/pre-push` runs that complete local proof and refuses the push when
it fails. A review or merge must therefore cite a fresh `cargo xtask verify`
receipt bound to the exact candidate commit or tree; repository state alone is
not proof that the gate ran.

The hook is tracked, but it does not run merely because you cloned the
repository. It executes only where an agentOS-style delegate pins its digest in
`~/.agent/repo-hook-allowlist`, and an unregistered repository is passed over
silently. Register it per machine:

```bash
shasum -a 256 .githooks/pre-push
# append to ~/.agent/repo-hook-allowlist:
#   <absolute-repo-root> pre-push=<digest>
```

`cargo xtask verify` reports when this checkout's hook is unregistered or
pinned to a stale digest, and prints the exact line to add. Editing the hook
without re-pinning blocks every push until the allowlist is updated; that
tripwire is deliberate.

Gate logic lives in `.githooks/pre-push-gate.sh`, which is not pinned, so it can
change without re-pinning. The gate accepts only `CFCTL_PRE_PUSH_GATE=on`;
there is no proof bypass. It verifies the clean canonical checkout and rechecks
its branch, HEAD, pushed ref and source after verification. It creates no linked
checkout and strips inherited Git context from proof subprocesses.

One exact checked-out branch or one new annotated tag peeling to checked-out
HEAD may be published per push. Lightweight, moved, existing and non-HEAD tags
are refused. Tag admission proves source identity only; signed-artifact and
provenance verification remain mandatory in the release/publish lane below.
Neither the hook nor creating a tag makes release assets public.

Without the delegate, treat `cargo xtask verify` before every push as a manual
obligation.

## Making a change

Read `NORTH_STAR.md`, `ANCHOR.md`, and `LAYERS.md` before changing public
behavior or repository structure. They define the outcome, invariants, and
authority boundaries; this guide is their contributor-facing projection.

1. Identify the owning crate and the catalog capability or public contract.
2. Add a failing test or contract fixture that demonstrates the missing
   behavior.
3. Implement the smallest complete change with the least powerful mechanism
   that satisfies the requirement, including catalog metadata and documentation
   when the public surface changes.
4. Run `cargo xtask verify`.
5. For live behavior, use a selected non-production account and report the
   evidence class for every claim. Account-backed disposable mutations remain
   a separate, explicitly acknowledged smoke lane.
6. Describe blockers honestly. Unknown cost, entitlement, permissions,
   verification, or rollback is contract debt—not authority to execute.

Internal path dependencies must include the exact workspace version as well as
their local path; `verify` checks that by equality, because Cargo alone accepts
a stale pin. A version bump must therefore update every intra-workspace pin and
`QUICKSTART.md`'s download path in the same change. New licenses, registries,
Git sources, duplicate versions, or secret-scan exceptions require explicit
review; do not broaden `deny.toml` or `.gitleaksignore` merely to pass the gate.

Every `cfctl` example is linted against the single-sourced command tree in
`crates/cfctl-core`, at full subcommand depth, in all tracked files and in the
managed agent instructions. A stale or mistyped example fails `verify`
regardless of which file it lives in.

## Extending the runtime

Crate boundaries decide where a change belongs. `docs/v2-architecture.md`
carries the table with each crate's boundary; this file does not restate it,
because a second copy is a second thing to keep true.

## Release lanes

Three separate lanes, deliberately split so identity-bearing steps are never a
side effect of building:

- `cargo xtask assemble` builds Apple arm64/x86_64 and Linux musl arm64/x86_64
  **twice** and compares hashes, creates SPDX SBOMs and provenance, and renders
  the Homebrew formula and the checksum-verifying Linux installer. It stops
  before any Apple or Sigstore activity.
- `cargo xtask release` repeats that proof, then signs and notarizes both macOS
  binaries against explicit operator-supplied identities and signs checksums
  and provenance.
- `cargo xtask publish` rechecks every identity and uploads the complete
  four-platform set, one asset at a time, to an empty draft release.

Making a draft public is always a separate operator action.

The prebuilt v1.3.0 operator posture requires the identity-bearing lane. Publication is
admissible only after both macOS binaries pass Developer ID signing and Apple
notarization, and both `SHA256SUMS` and provenance pass Sigstore verification
against the certificate identity and OIDC issuer committed independently to
`SECURITY.md`. Reproducible
double-builds, SPDX SBOMs, checksums, and commit-bound provenance remain
independent requirements. The local `assemble` lane remains unsigned local
evidence; its rendered installer fails closed and its outputs must not be
published as v1.3.0.

Before `cargo xtask publish`, create `v1.3.0` as a new annotated tag at the
exact commit named by release provenance and push it without force. Read back
both the remote tag object and its peeled
commit; an existing or mismatched tag is a stop, never a replacement target.
The annotated tag is the release locator, not the artifact signature: Apple
signatures and Sigstore bundles carry that identity proof.

Create an empty draft GitHub release from the verified tag. Bind its release
ID, repository, tag, draft state, and empty asset set before invoking
`cargo xtask publish`. The publish lane rechecks that exact draft around each
upload and compensates only asset IDs observed during its own attempt; it does
not create the tag or draft and never makes the draft public. The local source
proof never uploads or publishes release artifacts.

An account-backed disposable token smoke test
(`tests/account-backed-smoke.sh`) is kept out of the local proof lane because
it mutates a real account. It requires an explicit disposable account,
profile, reviewed permission group, and acknowledgement gate before it mints,
rotates, revokes, and verifies one short-lived token.

See [SECURITY.md](SECURITY.md) for private vulnerability reporting and
[docs/v2-security.md](docs/v2-security.md) for the runtime security contract.

For a source-only release, publish the exact reviewed and locally verified
annotated tag with a release title and notes that say source-only. Upload no
prebuilt executable, checksum set, or installer manifest, and set GitHub latest
to false. This source publication does not invoke or replace the signed artifact
lane above. Local source bootstrap remains separate from public binary trust.
