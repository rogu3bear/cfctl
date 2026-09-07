# Conditional private R2 restore

`r2-restore-private-captured-object` restores one member of an
[authenticated private capture](r2-private-capture.md). Its consumer is an
application recovery procedure that separately establishes writer exclusion,
full database recovery and retention authority. A successful object operation
does not authorize releasing application writers.

The native transport uses the documented account S3 endpoint in the default
jurisdiction, with SigV4 signing inside cfctl. Callers cannot supply an endpoint,
S3 secret or arbitrary object bytes. The existing raw REST upload is not used.
Account-owned API tokens are supported; user-owned and bucket-item token policy
languages are not inferred. The selected API-token profile must be pinned to
the exact account. No fallback, profile selection, import or credential repair
occurs in this capability.

The call takes exact `account_id` and `bucket_name` selectors, no query options
or caller-provided conditional headers, and a closed JSON request:

| Field | Meaning |
| --- | --- |
| `source_capture` | Original `evidence_hash` and `run_id` |
| `source_object_index` | Original manifest member index, 0 through 999 |
| `current_capture` | Current `evidence_hash` and `run_id` |
| `expected_current` | `{"state":"absent"}` or `{"state":"present","object_index":N}` |
| `token_verification_evidence_hash` | Authenticated native account-token verification read |
| `token_policy_evidence_hash` | Authenticated native details read for that exact token |

Use `--source-file` for a separate, mode-0600 JSON declaration with exactly
`source_capture_directory` and `current_capture_directory`. Its parent and both
snapshot paths must be canonical, owned mode-0700 directories. Provider keys,
private paths, bytes and metadata values never enter public plan JSON or receipts.

Both snapshots must pass native capture verification, including the original
catalog, build and credential lineage. The original capture's 900-second window
and credential may have expired; these describe historical capture custody.
The current capture supplies the still-open execution window. The current token
reads must match the current catalog, build and selected profile generation, be no more
than five minutes old, identify the same active account-owned token, and show an
allow policy for `Workers R2 Storage Write` on that exact account. Explicit deny
policies and unsupported policy shapes are refused. Any declared token expiry
must extend beyond the execution window.

Before returning a plan, cfctl copies both complete authenticated snapshots to
new private directories under its managed runtime data directory:
`r2-restore-stages/<stage-id>/source` and `current`. It rechecks all bytes and
native provenance and binds the stage to the plan through a private store entry.
This preserves displaced bytes even if the original snapshot paths later change.
The two copies together are bounded by 600,000,000 object bytes and 40 MiB of
manifest data. Files are mode 0600, directories mode 0700, and every creation is
exclusive. Failed preparation may leave private partial files without a usable
plan. Successful and failed operations retain their managed files; there is no
automatic retention, cleanup, or authority to delete them.

The immutable plan target includes `object_key_sha256` and
`source_semantic_metadata_sha256` from that authenticated selection, alongside
the source byte digest/count. Approval and execution revalidate these digests
against the managed selection. Inspection matches the verification binding to
these plan fields independently of the observed values; it never fills missing
historical target fields from a later response.

`cfctl call` creates the usual hash-bound PlanV2. Inspect the exact operation,
account, stage, window, costs and warnings before `cfctl plans approve <id> --yes`
and `cfctl plans run <id>`. Approval and execution revalidate the managed snapshots,
selected credential generation and current token evidence. Storage, Class A/B
operations and applicable Infrequent Access retrieval charges remain ordinary
R2 usage; no bucket or retention policy is created.

For an existing object, native GET checks its expected ETag, SHA-256 and size;
an exact-member REST metadata read checks stored semantic metadata. PUT then uses
`If-Match` with that ETag. For an absent object, the complete current capture must
show absence, HEAD must return 404, and PUT uses `If-None-Match: *`. There is at
most one PUT. Redirects, transport retries and alternative targets are disabled.
An uncertain response, deadline, unexpected success shape or failed verification
requires read-only rectification. A rejected condition never becomes an
unconditional replacement, a retry or a deletion of extra keys.

The write and immediate readback share the current capture window of at most
900 seconds, including its opening instant and excluding its expiry instant.
At most five provider requests occur: two pre-write reads, one PUT
and two post-write reads. Object downloads total at most 600,000,000 bytes, the
upload at most 300,000,000 bytes, metadata responses total at most 4 MiB, and the
PUT response is bounded by 16 KiB. The absent path needs four requests. Each
metadata observation identifies one returned exact member; it does not claim
the prefix page is a complete bucket inventory.

Restore accepts only losslessly representable stored metadata: the six documented
HTTP fields, lowercase ASCII custom keys with ASCII values, and the documented
storage classes. Null/absent HTTP fields remain absent. Expiry must be representable
to a whole second. Unsupported fields, casing, whitespace, encodings, customer
encryption or headers exceeding the 8 KiB bound fail before PUT. New ETags and
modification times are observations, not reconstructed historical values. Readback
compares actual stored metadata, not serving headers that may include defaults.

**ETag conditions protect content identity, not atomic metadata identity.** A
concurrent same-body metadata change between the pre-read and PUT cannot be
excluded by this primitive. Receipts therefore always carry
`metadata_atomic_precondition: false`, `writer_exclusion_qualified: false`,
`retention_qualified: false` and `combined_recovery_ready: false`. Applications
must supply actual writer exclusion before relying on combined preservation.

`cfctl plans rectify <id>` can inspect a consumed, running or uncertain attempt
without replaying PUT. It rechecks historical private custody under the current
account-pinned credential, makes one fresh native account-token verification read,
then reads object bytes and stored metadata. Its bound is three provider requests,
300,000,000 object bytes, 2 MiB of object metadata, 64 KiB of token-verification
response data and 900 seconds. The token observation uses one request and refuses
pagination, oversized bodies and an unexpected envelope. It can verify
that the exact target currently matches the original capture; it cannot prove an
uncertain historical PUT occurred, renew write approval, or release writers.
Repeated read-only checks retain the original verification checkpoint. Each new
observation has separate authenticated evidence; a matching observation appends
closure without replacing or rewinding the consumed operation's journal.

`cfctl plans show <id>` and `cfctl plans status <id>` expose
`result.private_restore_verification` for this native capability. The producer
binds the operation, immutable plan content and request hash, original/current
capture references and member selection, target digest, both capture windows,
and expected bytes and stored semantic metadata before authenticating the
verification body. The actual caller labels the observation as
`immediate_post_write` or `read_only_rectification`.

Inspection authenticates the referenced descriptor and body as
`post_change_verification`, checks the strategy and successful actual readback,
and matches those bindings to the validated plan and authenticated capture
windows. Ordinary successful verification uses the first verification-response
checkpoint. A later successful rectification uses its closure reference while
preserving the first failed checkpoint. Original windows may have expired;
equivalent RFC3339 offsets retain exact instant comparison and the declaration
digest remains exact.

The observation must follow the recorded verification attempt. A later
rectification observation must also follow the first verification response when
its closure selects a different evidence reference. Both capture observations
and their authenticated descriptors precede the readback, whose authenticated
evidence precedes the selected journal checkpoint. These checks establish
historical ordering, not renewed freshness.

The projection has `qualified: true` and
`qualification: "authenticated_restore_verification"` only after that join
passes. It includes `binding`, `expected`, `observed`, `observed_at`, byte and
stored-metadata comparison results, the evidence hash/class/time, and the selected
checkpoint stage. Missing, historical-unbound, mismatched, failed or unauthenticated
evidence produces `qualified: false`, `qualification: "unqualified"` and a
value-free reason. Restore inspection derives its envelope verification result
from this qualification; it never inherits a passing result from plan status.
Other capabilities retain their existing inspection behavior.

An authenticated failed readback whose binding matches still exposes its expected
and observed digests/counts, individual comparison results and evidence identity,
with `readback_passed: false` and `qualified: false`. This preserves the historical
failure without promoting matching bytes alone to complete readback success.

This projection describes a historical authenticated observation. It performs
zero provider requests and reads no API credential or retained object file.
It neither changes the journal nor grants freshness, present retained-file
custody, write authority or proof of an uncertain historical PUT. Metadata
atomicity, writer exclusion, D1 recovery, retention and combined recovery remain
explicitly unqualified. There is no raw evidence dump or new signing authority.

The transport and semantic projection follow the primary
[R2 S3 API contract](https://developers.cloudflare.com/r2/api/s3/api/),
[R2 API-token derivation](https://developers.cloudflare.com/r2/api/tokens/) and
[AWS SigV4 request signing](https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sig-v4-header-based-auth.html).
The native signature test uses AWS's public example vector. Production endpoint
behavior still requires authenticated provider execution and post-change readback;
local fixtures do not establish live recovery.
