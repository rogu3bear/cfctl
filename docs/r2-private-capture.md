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

The body is `CaptureWindowV1`: `window_id` is a canonical UUID; `opened_at` and
`expires_at` are RFC3339 timestamps describing at most 900 seconds; and
`recovery_binding_sha256` is the raw lowercase SHA-256 of the application's
exact recovery declaration. That hash binds a declaration without qualifying
its D1, writer or retention claims. Caller booleans cannot enable recovery.

The executor makes two complete whole-bucket enumerations around the object
reads. Both passes share ten pages of 100 objects. Each inventory has a maximum
of 1000 objects and 300,000,000 bytes; reads must match enumerated size and ETag.
The total ten-page limit can prevent a larger inventory from completing both
passes. It is never raised implicitly. Each listing response has a 2 MiB bound;
the retained manifest has a 20 MiB bound. Missing terminal pagination, duplicate
keys, repeated/missing cursors, changed metadata/population, stream errors,
deadline or resource exhaustion all fail. Requests do not retry or redirect.

Zero-byte objects and a terminal empty bucket are valid capture populations.
Absence/null HTTP metadata remains absent/null. The entire provider list record,
including custom metadata and unknown fields, stays in the private manifest.
Unsupported known identity/metadata shapes and customer-encrypted objects are
refused. The manifest records `last_modified` and any additional provider
version/upload observation actually returned; cfctl invents none. Two matching
observations do not establish a writer-controlled interval.

`manifest.json` and generated `object-NNNN.bin` files use mode 0600. Keys never
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
