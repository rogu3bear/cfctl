# Governed Maildesk reply containment

Maildesk supplies the committed `maildesk_reply_containment_v3` workspace
contract. cfctl supplies its native validation, authenticated evidence, fixed
D1 statements, approval lifecycle, and readback. The three capabilities share
that contract but perform different work:

| Capability | Purpose |
| --- | --- |
| `star-maildesk-cf.reply-containment-pre-read` | Read the exact related relay, admission, and claimed attempt before planning. |
| `star-maildesk-cf.reply-containment-apply` | Create a PlanV2 for one fixed containment operation. Calling it does not execute the write. |
| `star-maildesk-cf.reply-containment-read` | Inspect the original plan's outcome and return an authenticated, body-free receipt. |

Version 2 inputs are refused. They did not define an authoritative producer for
their provider-result and previous-containment hashes. An admission-v1 contract
remains a separate protocol; it cannot be used as containment authority.

## Prepare the exact request

Use a clean registered Maildesk checkout with the supported committed operation
pack, its pinned compiler and Bun runtime, and its exact private D1 config. The
request identifies the current source HEAD and tree, selected cfctl build,
profile, account, database, and credential generation. cfctl independently
checks those identities. A changed source, executable, generation, config, or
compiler requires a new request and plan.

The application prepares a mode-0600 JSON file with schema version 3, the
action, current candidate and control-plane identities, a new controller
transaction, the source route/relay/admission IDs, a reason, and the request
time. The controller's correlation and scope must match the observed source
admission. The request contains no claimed database snapshot. A replacement
also names an already-existing replacement relay and the authenticated storage
hash of a prior successful containment read.

No SQL, token, message body, subject, recipient address, or caller claim of
success is accepted. Input files and retained private stages must satisfy the
native ownership, permissions, size, and no-link checks. The runtime data root
used for containment staging must be a canonical, owned mode-0700 directory.

Inspect the generated guide before any authorized provider operation:

```bash
cfctl guide star-maildesk-cf.reply-containment-pre-read --json
cfctl call star-maildesk-cf.reply-containment-pre-read \
  --profile <profile> --account <account-id> \
  --selector account_id=<account-id> --selector database_id=<database-id> \
  --query config=<absolute-private-config-path> \
  --source-file <mode-0600-request-json> --json
```

The pre-read independently observes source relationships and any original
claim. Its attempt observation describes durable database state, not a fetched
provider response or proof of mail delivery. It retains the literal attempt
status, hashes the provider message ID, and distinguishes SQL NULL from empty
bytes. Raw provider message IDs never enter the public receipt or plan.

Preserve the returned native envelope as the `pre_read` field in a new private
plan-input file alongside the unchanged request fields. cfctl authenticates
the stored original envelope; a locally authored lookalike cannot qualify.
Requests and observations have a five-minute freshness ceiling. Pre-read must
follow the request, and the same request time and content remain bound through
compilation and approval.

## Plan, approve, and execute

Obtain the separately authorized fresh recovery-bookmark proof required by the
guide, then call `star-maildesk-cf.reply-containment-apply` with the same
selectors and config and the private plan-input file. Inspect the resulting
PlanV2 before approving its exact operation ID.

Containment revokes authority and requires explicit approval. Its atomic
Wrangler D1 file import temporarily makes database queries unavailable. Review
that effect, the bound database, the fixed row changes, and the recovery
conditions before execution.

```bash
cfctl plans show <containment-operation-id> --json
cfctl plans approve <containment-operation-id> --yes --json
cfctl plans run <containment-operation-id> --json
```

The three actions have different effects:

- `pre_send_rollback` revokes one active relay and its still-matching admitted
  or claimed admission, then records quarantine and plan outcomes. A race to
  the send boundary aborts the entire import.
- `post_boundary_containment` revokes remaining relay authority and records
  quarantine while preserving the entire original admission. It cannot unsend
  a message, correct it, retry it, or turn an unknown delivery into success.
- `replacement` records a relationship to an existing fresh relay on the same
  route and thread. It requires authenticated prior containment, preserves
  quarantine, and creates no relay, token, admission, or send.

Immediately before dispatch, cfctl rechecks local authority and freshness.
Inside the atomic import, the source, claim, and attempt predicates must still
match. A zero-row update raises an error; a later statement failure rolls back
the preceding changes. Retained private SQL and operation evidence are never
overwritten to retry a consumed plan.

## Read the original outcome

Use the identifiers from the inspected PlanV2 and compiled candidate:

```bash
cfctl call star-maildesk-cf.reply-containment-read \
  --profile <profile> --account <account-id> \
  --selector account_id=<account-id> --selector database_id=<database-id> \
  --query config=<absolute-private-config-path> \
  --query containment_transaction_sha256=<transaction-hash> \
  --query semantic_bundle_sha256=<bundle-hash> \
  --query plan_content_hash=<PlanV2-content-hash> \
  --query containment_operation_id=<containment-operation-id> --json
```

The read loads the original immutable plan and private candidate. An approved
but unconsumed plan is not execution evidence. A journaled uncertain attempt
can be inspected without replaying it. Exact cardinality and all relational
outcomes are required for `performed`; an incomplete match remains `ambiguous`,
including when one row exists but does not prove the complete outcome.

The public ResultEnvelopeV2's `result` contains a
`maildesk_reply_containment_stored_read` wrapper. Its `content_hash` addresses
the authenticated inner native envelope. The application passes that wrapper
to its readback validator. This storage hash, the semantic bundle hash, the
canonical pre-read receipt hash, and PlanV2's content hash are distinct
identities and cannot substitute for one another.

After a timeout, response loss, or failed verification, inspect the original
operation with `plans status`, the containment read, and the applicable
`plans rectify` procedure. Never issue a fresh send or replay the write to
resolve uncertainty. Database restoration needs separate authorization and
must preserve accepted or unknown-send history.

Source qualification, cfctl installation, catalog adoption, provider execution,
and pilot activation remain separate steps. Installing this adapter does not
adopt a catalog or run a containment operation.
