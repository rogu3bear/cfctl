# Worker module upload admission

`worker-script-upload-worker-module` remains discoverable but blocked. Its
generic call path does not implement a private, hash-bound multipart source or
multipart transport. Supplying metadata, broadening accepted permission names,
or looking up pricing cannot admit that upload. The core contract and request
builder reject it even when a retained catalog declares the former settings-ID
verification strategy.

Cloudflare's [upload operation](https://developers.cloudflare.com/api/resources/workers/subresources/scripts/methods/update/)
requires multipart form data. The
[settings GET](https://developers.cloudflare.com/api/resources/workers/subresources/scripts/subresources/script_and_version_settings/methods/get/)
returns settings; its declared result does not contain the script ID or content
ETag required by the former verifier. An in-memory fixture containing those
fields is not evidence that the provider returns them.

The guide therefore identifies the missing transport/verification contract and
returns no runnable call or pricing-search loop. No alternative upload is
automatically selected. The native `worker-deployment-plan` compiler is preview
only. `wrangler.versions-upload` with frozen-artifact mode is a separate
version-upload operation with registered clean source/configuration and
producer requirements; it is not an equivalent transport for an arbitrary
prebuilt multipart activation.

## Complete publication assessment

For a publication containing private objects and a Worker activation, qualify
both stages before declaring a working lane:

1. Bind the exact account, bucket, fresh prefix, Worker, hostname, artifact
   manifest, source/build identity, metadata and module identities, one executor
   and recovery custodian. Preserve the admitted effect and request/byte/cost
   bounds. Source qualification does not establish provider admission.
2. Recheck current Worker/version/settings and protection, prefix vacancy,
   protected data, schedules and preserved bindings. Changed inputs invalidate
   the frozen operation. Keep the original source and recovery artifacts.
3. Stage one non-sensitive canary and establish private protection before
   manuscript bytes. Then stage only the manifest's fresh private object keys,
   preserving each declared content type, length and digest. Verify every
   object by independent size and downloaded SHA-256 readback. No old-key
   overwrite, automatic retry or deletion follows from staging authority.
4. Activate exactly the admitted multipart body once. Read back the active
   version, decode and compare every module, and compare the complete settings
   and preserved bindings. An upload response or settings ID alone cannot prove
   this. Retain the previous version/configuration/prefix; compensation is its
   own admitted effect and does not restore storage or reverse external effects.
5. Complete the application's authenticated reading/review and mobile/page
   checks plus anonymous denial and alternative-host closure. An uncertain
   write stops affected dispatch and requires actual-state reconciliation;
   never replay it to test recovery.

The existing native `r2-put-object` primitive is create-only and privately stages
one mode-0600 source file, with at most 300,000,000 bytes. Its declared content
types are only `application/json` and `application/octet-stream`. Its MD5/ETag
and conditional-read verifier is not a bulk downloaded-SHA-256/privacy verifier.
Do not relabel PDF, CSS, JavaScript or other frozen content types to force that
primitive to accept a manifest. Deployment plan sets have at most 256 children;
they do not create a single arbitrary-size publication or aggregate new
mutation authority. Existing R2 permission and privacy checks remain necessary.

A complete new native lane would need managed multipart staging, source and
metadata validation, exact request/byte bounds and private transport, matching
module/settings verification, durable no-replay rectification, and coverage for
the complete object manifest and its content types. Those requirements must be
implemented and qualified together before the endpoint can become available.
This correction does not implement or advertise that lane.

## Adoption and recovery

Qualified source, merged source, installed PATH runtime, active catalog and an
approved operation are different states. This guard/guide correction needs the
normal review/integration, explicitly authorized supported installation and
catalog adoption before the installed guide changes. Preserve the prior PATH
artifact and runtime/catalog preimages for owner-controlled recovery; never
install or refresh the shared runtime merely to make a source receipt green.

Where an existing human-authorized publication-method exception applies, its
incumbent executor must reconcile the exact frozen plan/effects with the current
human publication instruction and record actual operation-bound adoption under
that exception. A tooling source worker does not grant that adoption or create
a native PlanV2/approval receipt. An existing exact-plan decision must not become
a duplicate generic method-approval question. A method exception does not erase
current-state, data/protection, canary, request/byte/cost, recovery or live-use
gates. If an additional decision is claimed, identify the actual governing rule
and unmet effect-bound decision rather than infer one from this native blocker.
