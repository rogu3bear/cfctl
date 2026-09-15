# Reviewed D1 read inventories

Application repositories can own a finite D1 read population in a committed
`.cfctl/operations/d1-reads.toml` pack. `cfctl` loads the operation by its declared
ID from explicitly registered, clean repositories. The account, database,
profile, source inputs, SQL, dependencies, witness population and output policy
are fixed in that committed contract. Generic D1 SQL/raw and Wrangler D1 remain
unavailable through this route.

The public types are in
[`cfctl-core::d1_read_inventory`](../crates/cfctl-core/src/d1_read_inventory.rs).
The [synthetic fixtures](../crates/cfctl-workspace/tests/fixtures/d1-reads) include
the pack template, complete inventory, call body, invalid final write, qualified
provider response and rejected response containing an extra row field.
The `reconciliation-*` fixtures add a separate synthetic three-query consumer,
including numbered result-derived parameters, an exact COUNT row, an invalid
caller-supplied parameter body and an empty COUNT response that must be rejected.

## Pack and source identity

`D1ReadPackV1` has `schema_version: 1` and `operation` declarations. Each operation
has `id`, `title`, `description`, `account_id`, `database_id`, `profile_id`,
`source_revision`, `source`, `inventory_path` and `inventory_sha256`. Each source
entry contains a repository-relative `path` and `sha256`.

Digests use `sha256:` followed by 64 lowercase hexadecimal digits. They cover
exact file bytes, including newlines. Source revision is a full 40-character
commit ID and must be an ancestor of the pack's current HEAD. Every declared
source input must match both that revision and the current checkout. The pack
and inventory themselves must be committed at HEAD. The loader derives their
current HEAD, tree, origin and pack digest; the pack never embeds its own future
commit ID. Add or update the pack in a successor commit after the source
revision exists. Symlinks, path traversal, ignored/untracked inputs, duplicate
operation IDs and changed inputs fail closed.

## Inventory and SQL

`D1ReadInventoryV1` declares `query_count`, `witness_count`, `tables`, `functions`,
`limits` and ordered `queries`. A table declaration is only its name and column
names. The local compiler creates empty ordinary tables; it never runs
application migrations, views, triggers, business writes or supplied DDL.

Each query contains `id`, exact `sql`, its `sha256`, `phase`, `requires`, `parameters`, `output`
and `witnesses`. Queries execute once in this order. Witnesses retain their
unique `id`, contiguous one-based `ordinal`, `group` and `source_reference`.
Deduplication may combine SQL only while retaining every original witness.

A dependency identifies an earlier `query_id`. Both `column` and `equals` are
either null, requiring the earlier read to succeed, or supplied together,
requiring a validated earlier result row with that exact field value. An absent
table or column can therefore prevent a dependent read without issuing it.
Independent later queries can still run. A transport/response rejection,
identity drift, deadline or resource stop prevents further dispatch.

SQLite prepares the entire selected inventory under a deny-by-default read
authorizer before credential access. Supported shapes are one SELECT,
nonrecursive WITH/SELECT, direct `table_info`/`foreign_key_list`/`foreign_key_check` PRAGMAs, and
SQLite-owned `sqlite_sequence(name, seq)` metadata and table-valued `pragma_table_info`, `pragma_foreign_key_list`,
`pragma_foreign_key_check`, `pragma_index_list` and `pragma_index_info` reads. Only declared main-table columns and compiler-approved functions are
accepted. Undeclared or caller-supplied parameters, multiple statements, DDL/DML, EXPLAIN, transactions,
attachment, configuration PRAGMAs, recursive CTEs, extension calls and
unrecognized authorizer actions are rejected. There is no query subset or SQL
override in the call body. Separate consumers, including postdeploy
reconciliation, need their own reviewed inventory.

### Parameters from earlier qualified results

`parameters` defaults to an empty array and permits at most 16 entries, ordered
by consecutive one-based `index`. SQL must use exactly those numbered SQLite
placeholders (`?1`, `?2`, ...). Bare `?`, named placeholders, missing indices,
extra placeholders and unused declarations are refused during full preflight.

Each entry declares `index`, `from_query`, zero-based `row_index`, `column`,
`kind`, `trim`, `nonempty` and `max_bytes`. `from_query` must name an earlier
query in this same inventory; its declared output column must have the same
scalar kind. `row_index` must be below that source's `max_rows`. For text,
`max_bytes` must be positive and no larger than the source column bound.
`trim: true` uses JavaScript `String.trim` whitespace semantics. `nonempty`
applies after trimming. Other kinds require `max_bytes: null`, `trim: false`
and `nonempty: false`. Parameters never accept null. Organization identifiers
are bounded text; the contract does not impose UUID syntax.

The Executor binds actual JSON scalar values only from the declared row of an
earlier qualified receipt in this run, under the same account, database and
credential generation. Values are sent as D1 bind parameters, never interpolated
into SQL. Missing or invalid source values leave dependent reads unattempted
with `parameter_source_unsatisfied`. Independent later reads may continue.
Source and credential checks still precede every dispatch.

## Output policy and execution bounds

`output.columns` declares every returned field: `name`, `kind` (`integer`,
`real`, `text`, or `boolean`), `nullable`, `max_bytes`, `allowed_values`,
`min_integer` and `max_integer`. The optional integer bounds are inclusive and
are valid only for `integer` columns; absent bounds deserialize as null.
Integers must be JSON integers representable as signed 64-bit values; reals
must be finite JSON floating-point values. Numeric strings are not coerced.
`max_bytes` is mandatory for text and null for other kinds. A non-null
`allowed_values` array restricts values further. Missing/extra fields, wrong
types, disallowed values, oversized strings or unexpected provider metadata
are rejected **before durable observation persistence**. Rejected provider
material is not included in errors or partial receipts.

The ordinary compiler ceilings are 512 queries, 1024 witnesses, 8192 bytes per SQL
statement, 4 MiB total SQL, 1000 rows and 64 KiB per provider response, 16 MiB
total provider response bytes and a 600-second run deadline. Each query's
`max_rows` and `max_bytes` can lower its limits; `min_rows` declares its minimum
output cardinality (default zero). A COUNT
consumer must explicitly set `min_rows: 1`, `max_rows: 1`, a nonnullable integer
column, `min_integer: 0` and its own maximum (for example 9007199254740991 for
a JavaScript safe integer). An empty COUNT response is rejected, never zero.
The full response JSON counts toward its byte bound. `limits` contains `max_total_response_bytes`,
`max_elapsed_seconds` and `stop_after_rows_read`. Requests are serial, have no
automatic retry, and have a maximum 30-second client timeout.

Output limits do not cap scanned rows. The cumulative rows-read stop prevents
later requests; it cannot cap an in-flight query's scans or currency charge.
Cancelling the client also does not prove immediate server cancellation. An
authority requiring an unestablished hard monetary bound must withhold that
execution. See [D1 limits](https://developers.cloudflare.com/d1/platform/limits/)
and [D1 pricing](https://developers.cloudflare.com/d1/platform/pricing/).

### Committed private output

Compiler version 2 adds an optional, closed `private_output` disposition to
`D1ReadInventoryV1`. Existing inventories omit it and keep all ordinary limits
and output behavior. An older binary rejects the new field. The pack, source
loader and inventory schema version remain version 1.

```json
"private_output": {
  "schema_version": 1,
  "format": "workspace_d1_private_read_v1",
  "max_artifact_bytes": 8388608,
  "require_primary": true
}
```

This disposition requires exactly one query, one statement, no dependencies or
parameters, and exactly one declared result row (`min_rows = max_rows = 1`).
The existing SQL/function/column/witness rules still apply. The query's entire
response bound may be 512 through 8,388,608 bytes; the total response bound must
equal it. Each text-cell bound is positive and no greater than the response
bound. The artifact bound is separately 1 through 8,388,608 bytes. Framing,
escaping and source/identity bindings count: a payload that fits a cell can
still exceed either outer bound. Oversize output fails; it is never truncated
into success. The deadline is 1 through 30 seconds.

For this disposition the existing `call` requires `--out <new-private-file>`.
The destination parent must already exist as a canonical, owned mode-0700
directory. Missing output, an existing entry, links, or incompatible output
flags fail before credential access. `--out` cannot enable private mode or
override committed bounds. `--value-out` is not supported on D1 reads.

Private execution sends `Accept-Encoding: identity`, refuses nonidentity
responses, disables retries and redirects explicitly, and requires HTTP 200,
empty `errors` and `messages`, one qualified result set/row and
`served_by_primary: true`. Missing or false primary metadata fails closed. No
session/bookmark input or cross-request freshness fence is introduced. A
successful read does not prove no later write occurred.

Duplicate JSON object keys at every outer-response depth and trailing JSON
input are rejected before qualification. The full qualified provider object is
retained; outer whitespace is not preserved. Text cells are opaque, so an
application's inner JSON text retains duplicate keys, malformed content and
whitespace for its own validator. Failed provider bodies are discarded.

The monotonic deadline covers request, body read, parse, qualification and
artifact preparation/publication, with checks around bounded synchronous work.
Cancellation ends client work, without promising immediate server cancellation.
The body reader retains at most its declared bound and detects the first excess
chunk before parsing; the HTTP/TLS stack may temporarily buffer a larger chunk.
There is no pagination, continuation, scan ceiling or hard currency guarantee.

`D1PrivateReadArtifactV1` contains version/kind, a typed binding to the complete
workspace contract, capability/catalog/build/profile/credential/query identities,
UTC start/completion timestamps, qualified transport metadata, and the full
`provider_response`. The transport records one attempted query, identity
encoding, primary execution and `application_predicates_evaluated: false`.
Its schema is owned by the public Rust types linked above. Application policy,
schema, SQL, history bounds and provenance validation remain with the source owner.

Publication stages mode-0600 bytes within the pinned private directory, syncs
and reads them back, then atomically renames without replacement. Existing
secret-file replacement behavior is unchanged. Failed stages clean only this
invocation's matching temporary entry. A failure after publication preserves the
file for reconciliation and reports incomplete custody, never a qualified
artifact or an automatic replay.

Normal `ResultEnvelopeV2` output and observation evidence contain only fixed
classifications, identity bindings, structural counts and artifact path/byte
length/SHA256. Provider values, provider diagnostics and value-derived hashes
are absent. `performed` reports whether dispatch was attempted; `read_complete`
requires both transport qualification and verified artifact publication. The
artifact hash is external to its own bytes. Application predicates still require
the owner's separate validator, and any later mutation requires its own authority.

## Public call and caller result

First register the intended repository and inspect the exact operation with
`cfctl catalog show <operation-id> --json` and `cfctl guide <operation-id> --json`.
Both public discovery paths run the complete local inventory compiler as part
of loading this workspace capability. They do not execute the D1 population.
Resolve and approve the actual provider read scope separately from pack review.
Then use the existing public call surface:

```sh
cfctl call example.d1-read-inventory \
  --profile example-read --account aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --selector account_id=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --selector database_id=11111111-2222-4333-8444-555555555555 \
  --body-stdin --json < call.json
```

The only body fields are `inventory_sha256` and
`expected_credential_generation_id`. Both profile and account must be explicit
and match the committed declaration. The selected profile must be an
account-pinned API token with the exact current credential generation. The
ordinary CLI runtime lock prevents concurrent token import; source and profile
metadata are also checked again before each request. The catalog must already
be available; catalog synchronization is a separate operation.

The outer `ResultEnvelopeV2` retains `capability_id`, `profile_id`, `account_id`,
`operation_id: null`, `performed` and attested evidence. `result.kind` is
`workspace_d1_read_inventory_v1`. `result.execution` is
`D1ReadInventoryResultV1`; `read_complete` means every required query returned
a qualified response. It does not mean an application's schema or integrity
predicate passed. `application_predicates_evaluated` is always false.

Each ordered `result.execution.results` entry retains query ID/digest, phase,
witnesses, `status` (`complete`, `rejected`, `unattempted`), `attempted`, fixed
classification, HTTP status, rows read, response bytes and `receipt`. A complete
receipt preserves the qualified provider JSON separately from any compatibility
projection. Its validated rows are at `receipt.result[0].results`. Rejected and
unattempted entries contain no provider body. A partial population returns
`ok: false` with `CFCTL_D1_READ_INCOMPLETE` and explicit attempted/unattempted
counts. Do not replay it automatically or treat missing results as an empty
successful array.

`parameter_provenance` contains the index, source query ID and SQL digest,
source row index, column and `value_sha256` of the exact bound JSON scalar.
It contains no additional plaintext value. Before the actual observation store,
cfctl requalifies all receipts and recomputes these provenance joins and hashes.
Unattempted entries have empty provenance. The qualified source receipt is
retained only under its own declared output policy.

For the three-read reconciliation consumer, all three fixed reads may complete
before the application evaluates its local predicates. This changes the timing
of the aggregate read on cases where the old local processing threw earlier;
the application must retain its existing pass/refusal rules. cfctl does not
interpret business facts or implement a continuation engine.

Application adapters must retain the native envelope and validate its identity,
completeness and all query/witness joins before evaluating predicates. Legacy
Wrangler-array consumers may receive a separate qualified projection of the
specific `receipt.result` array. Name checks must inspect its typed result rows
only, never SQL text, diagnostics or evidence metadata. Read-specific adapters
must leave shared migration, seed, backup, restore and cleanup helpers intact.
