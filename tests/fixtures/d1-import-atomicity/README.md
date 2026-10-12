# Isolated generic D1 import qualification inputs

These synthetic inputs prepare a provider qualification decision. They do not
qualify D1 transaction behavior or authorize resource creation, SQL execution,
cleanup, production changes, or credential changes.

`seed.sql` is the original synthetic Sign fixture emitted by `original_fixture()`
in frozen jkca-web commit `749167e0401d00864cd691db66d95470bf74597c`,
`scripts/test_sign_writer_protocol.py` SHA-256
`eeaad2f4d4529401acb7fe5a4ad37e21bca11b5caf303bd2220323cc2a79fab5`.
SQLite dump transaction delimiters are omitted for the D1 import protocol. The
three synthetic legacy rows and allocated signature sequence are preservation
witnesses. The schema-migration row is synthetic fixture data for this isolated
original-state model; it asserts nothing about any installed production ledger.

`fail-after-update.sql` retains the exact frozen initial-open program and inserts
one deliberately failing `CHECK` immediately after its control-row update. Its
expected outcome is a rejected import with the entire before-state unchanged,
including absence of `sign_recovery_command_assert`. This distinguishes whole
file rollback from statement-only failure. Never treat a provider error response
alone as proof of rollback.

The existing frozen application owns the other two exact source programs:

- `cloudflare/sign-worker/sql/bootstrap_v7.sql`, SHA-256
  `a611a61461a0e9fef9a1bcea332391507d37b2301c4dfaf4ac2593c30b965f00`.
- `cloudflare/sign-worker/sql/open_admission.sql`, SHA-256
  `378a164cf562c2f867d65c1a4f76fb0d9f79ca325699698441d97cc3a55d5d50`.

Run the local fixture checks against the unchanged clean linked checkout:

```sh
python3 -B tests/fixtures/d1-import-atomicity/verify_local.py \
  --sign-source /absolute/clean/jkca-web
```

This checks exact source identity, fixture provenance, local SQLite rollback,
success, stale initial-state rejection, preservation, and sensitivity to a
simulated non-atomic executor. SQLite is explicitly wrapped in a local
transaction. That wrapper is not part of the uploaded SQL and is not evidence
that the Cloudflare import service supplies the same transaction boundary.

The proposed governed exercise uses one separately approved disposable D1
lifetime, never the production Sign or Founder database. Bind its actual UUID
to the approved create operation and every later immutable plan. With a freshly
qualified purpose-scoped profile and catalog, obtain a complete authenticated
`d1-full-export` before every `d1-import-database` plan. Each source file must be
tracked at its clean exact Git HEAD; fixture and frozen application roots may
be different, and each plan retains its own source authority.

The ordered cases are seed, exact bootstrap, deliberate failure after update,
exact initial-open success, then the same initial-open program against the
already-open state to test invalid-initial-state rejection. Each is a new,
separately reviewed operation ID; none is a replay of a consumed operation.
Complete authenticated full exports after each terminal result supply the
complete synthetic populations and schema for comparison. Require closed
protocol 7/epoch 1/revision 1 before opening, then open 7/2/2 only on success.
Both rejected cases must preserve the complete before-state and leave no
assertion table. Success may change only the intended control row; saved legacy
rows, counters, migration/certification receipts and guards must be preserved.

Stop if any response, polling boundary, export, identity, or comparison is
uncertain or differs. Preserve the original plan, stage, checkpoints and exports;
use only its supported status, poll-child or rectification path. Do not repeat
an import, reset the fixture, or restore over possible concurrent work. Cleanup
is a separately approved exact-UUID deletion after classification and custody
review; it is neither automatic compensation nor evidence destruction.

The release proposal outside this source tree owns account/profile, resource
name, lifetime, size/cost limits, exact approvals and retained evidence. No
placeholder UUID or predicted receipt can be used as a live identity. Keep
production Sign issuance frozen and its separate 900-second admission contract.
