# Private R2 capture

`r2-capture-private-bucket` is a native capture component. It does not establish
that an application can recover. The application must separately qualify actual
writer exclusion, its full D1 export/bookmark and integrity sidecar, admitted
destination/retention, conditional object restore, and combined restore readback
before releasing writers.

The public call uses exact `account_id` and `bucket_name` selectors, a closed
JSON body, and `--out <new-absolute-snapshot-directory>`. The directory's parent
must already be an owned mode-0700 custody root with a canonical path. Every
snapshot is new; existing files and directories are never replaced. This is
private backup material and belongs outside task outputs and repository files.

The closed body is `CaptureRequestV2`:

```json
{
  "schema_version": 2,
  "window": {
    "window_id": "<canonical UUID>",
    "opened_at": "<RFC3339>",
    "expires_at": "<RFC3339>",
    "recovery_binding_sha256": "<64 lowercase hex characters>"
  },
  "token_verification_evidence_hash": "sha256:<digest>",
  "token_policy_evidence_hash": "sha256:<digest>"
}
```

The four-field window remains `CaptureWindowV1`, at most 900 seconds. Its hash
binds the application's recovery declaration without qualifying D1, writers or
retention. Old flat-window requests reject with migration guidance. CF's next
fresh preparation input must change; existing application manifest consumers do
not need a source change. Never rewrite or replay historical failed windows.

Capture requires an account-owned API-token profile pinned to the exact account
and generation, with authenticated account-token verification and policy reads
from the current build/catalog, no older than five minutes. The token must be
active throughout the window. Account-scoped Workers R2 Storage Read suffices;
an already-held Write grant includes read but capture never widens permissions.
Restore retains its separate Write gate. User-owned, bucket-item S3-only,
conditional and temporary-session policies, or nondefault jurisdiction are not
supported by this combined adapter. No token mint/renewal occurs during capture.
The existing signer derives its signing material internally; no separate secret
or token ID is accepted in the request. [R2 authentication](https://developers.cloudflare.com/r2/api/tokens/).

S3 ListObjectsV2 supplies two whole-bucket inventories. Before body reads and
after the final inventory, REST exact-member prefix reads require one exact key
and preserve the entire returned metadata record. Bounded collateral prefix
records are allowed; missing or duplicate exact members fail. REST pagination
absence/null is irrelevant to this positive member lookup and never proves
bucket completeness. S3/REST key, ETag, size, modification instant and storage
class must agree; both inventories and both complete metadata observations must
match. No timestamp tolerance or metadata defaults are invented.

The S3 query is closed to `list-type=2`, `max-keys=100`, `encoding-type=url`, and
a provider-issued continuation token. URI-encoded keys decode exactly once;
continuation tokens stay opaque. Strict XML accepts namespace-equivalent names,
optional declaration, and equivalent empty elements; optional echoes are checked
only when present. One explicit IsTruncated=false with no nonempty next token is
required to finish. True requires a fresh bounded token, regardless of row count.
Malformed XML (including HTTP 200), DTD/custom entities, unknown shapes, duplicate
fields/keys, filters, or ambiguous terminal evidence fail closed. [S3 compatibility](https://developers.cloudflare.com/r2/api/s3/api/),
[ListObjectsV2](https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjectsV2.html).

Both inventories share ten pages of 100 objects: the existing 1000-object
admission ceiling permits at most 500 objects to complete both passes. Body
reads share 300,000,000 bytes. P list + 2N metadata + N body requests are bounded
at 3010 attempts; each XML/metadata response is at most 2 MiB, aggregate XML at
20 MiB and aggregate metadata at 40 MiB including collateral rows. Each retained
metadata pass and the complete manifest are bounded at 20 MiB. Ordinary R2
request/retrieval usage applies to all these reads. No bucket or policy is created.
Requests run serially without retry, redirect, decompression or fallback, with
60-second per-request limits inside the unchanged absolute window. Bounds and
final post-I/O time are checked before a success receipt; encoded bounds do not
promise an OS RSS limit or forcibly preempt filesystem sync.

Zero-byte objects and a terminal empty bucket are valid capture populations.
Absence/null HTTP metadata remains absent/null. The entire provider list record,
including custom metadata and unknown fields, stays in the private manifest.
Unsupported known identity/metadata shapes and customer-encrypted objects are
refused. The manifest records `last_modified` and any additional provider
version/upload observation actually returned; cfctl invents none. Two matching
observations do not establish a writer-controlled interval.

`manifest.json`, a bounded 4 KiB private `request.json` companion, and generated
`object-NNNN.bin` files use mode 0600. The companion reconstructs the exact v2
input hash for authenticated verification and follows captures into private
restore staging. Its removal or alteration cannot downgrade v2 proof to v1.
Historical captures without it retain their flat-window verification path;
manifest/receipt/verifier outputs remain version 1. Keys never
become local filesystem paths. Every file is re-read before publication of the
capture receipt. Failed capture may leave private partial files, but never a
complete authenticated success receipt. Preserve that residue for diagnosis;
it is not admitted recovery material.

`r2-verify-private-capture` accepts the same exact target selectors, a
`--source-file <snapshot-directory>`, and a closed body containing
`capture_evidence_hash` (`sha256:` plus the digest) and `capture_run_id`.
It makes no provider requests and performs no catalog refresh. It requires
authenticated native capture evidence and its matching operational proof,
then rechecks the exact private manifest and all file hashes, sizes and custody.
Historical capture proof retains its original catalog/build/profile generation.
It proves neither current provider state nor continuing writer exclusion.

The verification result names `qualification: authenticated_capture_integrity`.
Its `capture` field carries the exact run, target, window/declaration hash,
timestamps, page/object/byte counts and private manifest hash. Private object
keys, body bytes, metadata values and local paths never enter public receipts.
`recovery_ready` remains false. The writer, D1, retention and conditional restore
qualification fields remain false. Consumers must invoke this native entrypoint;
checking a self-authored JSON file or its hash does not authenticate a capture.

The generic raw R2 getter remains blocked. The existing create-only private
upload is not a recovery replacement operation. Current REST upload documentation
and Wrangler establish HTTP metadata headers but do not establish the required
custom metadata and conditional replacement contract. The documented S3 and
Workers binding interfaces are separate transports, not interchangeable headers
on the existing REST route. [Conditional private restore](r2-private-restore.md)
uses its own native S3 transport and consumed-plan contract.

After an attempted request, an incomplete capture retains
`diagnostic: private_capture_incomplete` and all existing incomplete flags. Its
`failure` contains only closed `stage` and `reason` codes, the one-based
`request_ordinal`, and optional `provider_http_status`. The status is reset to
null before each request and records actual received headers; it is not a claim
that the whole capture succeeded. Top-level `status: 0` is synthetic and is
explicitly marked `status_is_provider_response: false`.

Stages distinguish initial/final inventories and metadata passes, object reads, manifest,
and local verification. Reasons distinguish transport, HTTP response, body read
or bound, JSON/XML, envelope, pagination metadata/cursor/terminal evidence, object
identity/size, storage, drift, and window failures. Private bodies, keys, URLs,
provider messages, and credentials never enter these diagnostics. A diagnostic
from a later request cannot establish the cause of a historical failed capture.
Missing S3 terminal evidence remains incomplete. Diagnostics confer no permission
to retry or reuse expired windows.
