---
artifact: launch-checklist
version: "3.0"
status: active
launch_candidate: cfctl-site Workers production closure
integration_base: cee43d46aeee9dec0f76f223b613d069cef3e00a
candidate_binding: exact-clean-pr-head-plus-terminal-receipts
---

# `cfctl-site` production launch checklist

This is the coordination spine for the first production closure of the public
website. It binds one repository candidate to one Cloudflare Worker and keeps
source proof, review, merge, provider plan, approval, execution, live readback,
custom-domain attachment, CLI distribution, and OAuth promotion as separate
claims.

An unchecked item is not implied complete. Historical receipts are useful
context but never authorize or prove the current candidate.

## Scope decision

| Field | Bound value |
|---|---|
| Repository | `/Users/star/dev/cloudflare` |
| Integration branch | `main` |
| Source candidate | Exact clean PR head, then exact merged `origin/main` readback |
| Cloudflare account | `ca30e922fda7f5578e49873542e4aaca` |
| Worker | `cfctl-site` |
| Configuration | `/Users/star/dev/cloudflare/site/wrangler.toml` |
| Runtime | Cloudflare Workers + Workers Assets |
| First live target | The account-bound `workers.dev` hostname |
| Branded production target | `cfctl.com`, attached only after `workers.dev` verification |
| Analytics | None; content-free operational health only |
| Public OAuth | Disabled and outside this launch |
| Event-ingress bridge | Outside this launch |
| CLI binary release | Separate release train; not implied by website deployment |

Pages is not an alternative carrier for this launch. The source uses
server-rendered Leptos through a Worker entry point and a Workers Assets
binding. Any future Pages variant requires a new architecture and release
decision.

## Evidence vocabulary

- **Prepared**: exact clean source and reproducible artifact exist locally.
- **Planned**: `cfctl call` produced an immutable operation; Cloudflare did not
  change.
- **Approved**: the operator admitted one reviewed operation ID.
- **Executed**: the operation crossed the provider boundary.
- **Verified**: governed provider readback and the live-site verifier both
  passed for the expected deployment.
- **Blocked**: the named exit condition cannot currently be proved.

## Active task ledger

### A. Source and review

- [ ] Bind the exact PR head, tree, upstream, and clean-tree fingerprint.
- [ ] Review the complete `origin/main...HEAD` diff, including this checklist,
      the live verifier, and its gate integration.
- [ ] Run `CARGO_GATE_RESULT_TTL_SECS=0 cargo xtask verify` on the exact clean
      PR head.
- [ ] Obtain an independent adversarial review of that exact object.
- [ ] Publish one PR; do not split the source candidate across release lanes.
- [ ] Merge only after proof and review are current.
- [ ] Re-read live `origin/main` and prove the candidate is integrated.
- [ ] Re-run build identity checks from the merged checkout.

Exit evidence: exact PR head and tree, terminal local gate, review verdict, PR
URL, merged SHA/tree, and live remote-default readback.

### B. Artifact identity

- [ ] Record the terminal SHA-256 emitted by
      `site/scripts/verify-reproducible-edge.sh`.
- [ ] Confirm `site/wrangler.toml` still targets only `cfctl-site`,
      `build/_worker.js`, and `target/site`.
- [ ] Confirm no D1, KV, R2, Analytics Engine, durable object, runtime secret,
      or third-party script entered the release artifact.
- [ ] Verify the manifest binds the JS, Wasm, and CSS filenames to their
      content hashes.
- [ ] Preserve the exact source SHA and artifact hash in the Worker version
      message.

Exit evidence: exact merged source identity, artifact digest, manifest, and
successful Worker/source contract checks.

### C. Account and rollback preflight

- [ ] Select a profile owned by `cfctl-site`; do not reuse an AOS deployment
      profile merely because it points at the same account.
- [ ] Verify Workers Scripts Read and Workers Scripts Write without exposing
      credential values.
- [ ] Run `cfctl version --json`, `cfctl doctor --json`, and
      `cfctl agents doctor --json`; require exact source/PATH identity and zero
      instruction drift.
- [ ] Audit the registered workspace and confirm the site config maps to the
      intended account.
- [ ] Read current Worker settings, versions, production deployments, routes,
      custom domains, and required secret names through governed capabilities.
- [ ] Record the previous production version UUID and prove it remains
      retrievable.
- [ ] Resolve the compensation path: a separate reviewed
      `wrangler.versions-deploy` plan targeting `<previous-uuid>@100`.

Exit evidence: profile ID and credential generation, permission inventory,
live-read receipts, current deployment identity, and rollback anchor.

### D. Inert version upload

- [ ] Create a `wrangler.versions-upload` plan using the absolute config path,
      exact Worker name, and source/artifact message.
- [ ] Review account, profile, target, workspace impact, cost, permissions,
      warnings, verification, and lack of automatic uploaded-version deletion.
- [ ] Obtain exact operation-ID approval.
- [ ] Run the operation once.
- [ ] Inspect terminal status; never replay after a crossed or uncertain
      provider boundary.
- [ ] Read back the uploaded version UUID and expected message.
- [ ] Confirm production traffic did not change.

Exit evidence: upload operation ID, approval state, apply receipt, version UUID,
message readback, and unchanged traffic readback.

### E. Production promotion

- [ ] Create a separate `wrangler.versions-deploy` plan targeting exactly
      `<uploaded-uuid>@100`.
- [ ] Review the old/new version identities, traffic change, config, account,
      permissions, downstream-usage exposure, verification, and rollback
      warning.
- [ ] Obtain exact operation-ID approval.
- [ ] Run the promotion once.
- [ ] Inspect terminal status and read back the expected UUID at 100%.
- [ ] Confirm no unrelated Worker, binding, secret, route, or domain changed.

Exit evidence: promotion operation ID, approval, apply receipt, and governed
100% traffic verification.

### F. `workers.dev` runtime verification

- [ ] Run `bun ./scripts/verify-live-site.mjs https://<exact-workers-dev-host>`.
- [ ] Verify `/`, `/start`, `/security`, `/privacy`, `/terms`, the OAuth
      callback, and a true 404.
- [ ] Verify CSP, HSTS, framing, content-type, permissions, referrer, and cache
      headers.
- [ ] Verify callback query sentinels do not appear in server-rendered HTML.
- [ ] Verify the live asset manifest and each immutable JS/Wasm/CSS artifact.
- [ ] Complete keyboard, visible-focus, narrow layout, 200% zoom, reduced
      motion, and a second-browser pass on the exact deployment.
- [ ] Freeze promotion and execute the reviewed compensation lifecycle on any
      critical mismatch.

Exit evidence: verifier JSON, browser/runtime evidence, provider deployment
readback, and either go or compensated-state readback.

### G. `cfctl.com` attachment

- [ ] Resolve current Workers domain and DNS capabilities through `cfctl`.
- [ ] Use a credential lane with the exact read/write permissions required by
      those capabilities; do not broaden the Worker upload profile silently.
- [ ] Read current domain, DNS, and TLS state before planning.
- [ ] Create, review, approve, and run the domain operation independently from
      Worker promotion.
- [ ] Read back the Worker-domain association, DNS records, TLS validity, and
      HTTPS behavior.
- [ ] Re-run the live-site verifier against `https://cfctl.com`.
- [ ] Confirm site/domain work did not enable or alter OAuth.

Exit evidence: domain operation ID, provider/DNS/TLS receipts, and live-site
verifier JSON for `https://cfctl.com`.

### H. Operational go-live

- [ ] Name the go/no-go decision maker, incident commander, and backup.
- [ ] Name and test the public support and private security destinations.
- [ ] Accept privacy, terms, security, license, accessibility, and callback-log
      posture through named owners.
- [ ] Activate content-free availability, latency, error-rate, deployment-drift,
      and certificate-expiry monitoring.
- [ ] Prove callback queries and credentials are absent from observability.
- [ ] Record the final go decision only after all selected blocker evidence is
      terminal.
- [ ] Schedule T+1 and T+7 evidence reviews.

Exit evidence: owner acceptance, monitoring/readback, go decision, and review
schedule.

## Stop rules

- A plan is not an apply; an apply is not verification.
- Never replay a consumed plan or a run that may have crossed the provider
  boundary. Use status, resume, or rectify exactly as the capability guide
  directs.
- Never use raw Wrangler, HTTP APIs, MCP, or dashboard operations around a
  blocked or ambiguous `cfctl` capability.
- Never approve a plan before its exact account, targets, diffs, cost,
  permissions, warnings, verification, compensation, source SHA, and artifact
  identity are reviewed.
- Any source change after proof invalidates the artifact, review, and provider
  plan.
- A failed live-site check freezes custom-domain work and announcements.
- Publishing the site does not publish a CLI release or promote OAuth.

## Rollback contract

Rollback triggers include a wrong deployed UUID, route failure, security-header
regression, callback-value disclosure, immutable-asset mismatch, unexplained
provider drift, or inability to prove the running source.

1. Freeze announcements and further promotion.
2. Preserve the failing operation IDs and evidence; do not replay.
3. Create or refresh the governed compensation plan targeting the known-good
   previous version at 100%.
4. Review and approve that exact rollback operation.
5. Run it once, inspect terminal status, and repeat provider and live-site
   verification.
6. Keep the launch no-go until the compensated state is verified.

## Explicitly separate future work

- The prebuilt v1.3.0 CLI posture requires signed and notarized publication in
  `README.md` and `CONTRIBUTING.md`. Its trust-root binding, source merge,
  annotated tag, empty draft, signing,
  notarization, artifact upload, public-release transition, installation, and
  provider readback each retain separate receipts and remain outside this
  website launch.
- Public OAuth needs a separate security/privacy decision, client plan,
  callback configuration, log-redaction proof, approval, promotion, and revoke
  path.
- The keyring-core migration remains blocked on real Linux Secret Service
  runtime evidence and is not part of the website launch.

The site reproducibility log hashes paths relative to `site/` (`build/...` and
`target/site/...`). That comparison digest is local build proof. A cfctl upload
plan binds paths relative to the owning Git repository (`site/build/...` and
`site/target/site/...`) and computes its own `artifact_set_sha256`. Deployment
receipts and annotations must use the cfctl plan's digest; do not copy the site
reproducibility digest into that field.

A labeled source-only CLI release with no uploaded binary or installer assets
and GitHub latest disabled may accompany site publication without Apple
credentials. The site must keep source bootstrap distinct from authenticated
prebuilt installation and must not advertise nonexistent binary artifacts.
