# Farm content and revision snapshot

`farm-content-provenance-snapshot` is a read-only native capability for Farm's
`site_content` singleton and `site_content_revisions` history. It is pinned to
account `ca30e922fda7f5578e49873542e4aaca` and database
`2a220ff3-f718-430e-a45f-b0d186a46193`.

After the qualified runtime and catalog are adopted, inspect its generated guide:

```bash
cfctl guide farm-content-provenance-snapshot --json
cfctl call farm-content-provenance-snapshot \
  --profile <farm-d1-read-profile> \
  --account ca30e922fda7f5578e49873542e4aaca \
  --out <new-file-in-owned-mode-0700-directory> --json
```

The explicit, nonemergency API-token profile must pin that same account. The
catalog requires **D1 Read**; Cloudflare enforces the token's grant. Caller SQL,
table/column/target selectors, query controls, bodies and conditional headers
are rejected before credential access. Catalog synchronization is a separate
operation; this call does not refresh it automatically.

One fixed SQL statement observes both tables in the same SQLite read snapshot.
It retrieves only `id,schema_version,version,fields_json,updated_by,updated_at`
from the singleton and `version,schema_version,fields_json,saved_by,saved_at`
from the revisions. It preserves `fields_json` text and the current CAS version.
History must contain every version from 1 through the current version in order;
the latest revision must equal the current content and provenance. Version 0
has no revision. Missing rows, unknown schema, gaps, duplicate/reordered versions,
current/revision disagreement, malformed output and provider failures fail closed.

Limits are 1,000 revisions, an 8 MiB response/output, and a 15-second HTTP deadline.
A 1,001st revision is an overflow sentinel. There is no continuation, retry or
silent truncation. These client limits do not promise a hard provider scan,
execution-time or currency ceiling. An incomplete history needs separate source
qualification; do not treat a failed read as an empty history.

The output parent must be an existing owned mode-0700 directory addressed by its
canonical absolute path. The file must not exist. The runtime creates it as
mode-0600, checks private custody, syncs it, and compares a private readback before
returning its SHA-256. Existing files, links and replaced parents are rejected.
Only metadata (including current version/count) and the output content hash enter
stdout/evidence; content values, actors and timestamps stay in the private file.
If a later evidence write fails, a completed private file may remain: inspect
that destination rather than overwriting it or treating absence of a receipt as
absence of output. Incomplete newly created output is removed where custody
validation permits; an abrupt process exit may leave a private partial file.

The snapshot supports source-owner provenance analysis. It does not migrate,
restore, apply content, send email, or establish acceptance of any proposed edit.
