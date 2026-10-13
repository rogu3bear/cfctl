# Workspace D1 transition declarations, version 3

Version 3 compiles a complete source schedule for migrations that cross a Worker publication boundary. Its adapter is **blocked**. It creates no executable provider plan and cannot reuse the legacy Wrangler-ledger executor. Versions 1 and 2 retain their existing behavior and bounds.

The consumer is the registered workspace operation loader for `.cfctl/operations/d1-migrations.toml`. Set `schema_version = 3`; every `operation` uses the strict `Declaration` type in `cfctl-core/src/workspace_d1/transition.rs`. Unknown fields reject. One frozen pack must contain exactly one operation per scheduled target, with matching manifest, historical ledger, database scope, configuration and schedule. The loader checks every declaration and assertion source before returning the selected capability. A later target therefore does not require rewriting the pack or historical flags.

Each operation binds an exact target sequence, filename and source `{path, sha256, git_blob_oid}`. Sequence comes from the manifest, never a filename prefix. The manifest retains consecutive sequence numbers and adjacent historical predecessors. The separate schedule declares each step's `pre_deploy` or `post_deploy` phase, required completed transitions and exact deferred gaps. Every pending source identity appears once; the completed runtime sequence must equal the preceding schedule prefix. Historical membership is source evidence and establishes no provider-side migration history. Version 3 allows at most 256 manifest entries; version 2 retains its 64-entry baseline bound.

Four tracked assertion sources—`preconditions`, `capture`, `preservation`, `cleanup`—surround the original migration source. The compiler concatenates those five byte sequences without rewriting SQL, removing PRAGMAs or adding transaction statements. Each segment must be nonempty NUL-free UTF-8 ending in a newline. Total size is limited to 1 MiB. The result records source identities, segment offsets/lengths, compiler identity, complete byte length and SHA256. This binds reviewed bytes; it does not prove SQL syntax, assertion correctness, atomicity, or application preservation. The application owns those semantics.

Compiler revision `workspace-d1-envelope-v3.4` additionally records a separate
`workspace-d1-execution-v1` manifest. It binds exactly one compiler-owned
`INSERT INTO "d1_migrations" ("name") VALUES (...)` after preservation and before
cleanup, using the manifest-selected target filename as an escaped SQL literal.
The original five source segments and their envelope digest remain unchanged.
The execution manifest records ledger offset, length and digest, source envelope
digest, and the complete execution length/digest; the combined bytes retain the
1 MiB ceiling. Materialization revalidates that identity. This is deterministic
source preparation only: actual installed ledger columns/defaults, target-once
semantics, typed qualification and remote atomic failure behavior still require
proof. It neither bootstraps history nor enables a provider executor. Existing
Legacy execution remains closed. Native V4 admission and local proof derivation are implemented; live capability activation remains separately gated.

Runtime intake first reconstructs the envelope from the current clean, committed pack. It rejects a changed repository, declaration, compiler identity, segment order, offsets, lengths or bytes, and checks the complete envelope digest again. This source check creates no import stage or provider operation.

Fresh runtime references belong outside the tracked source. `RuntimeBinding` requires observed baseline, baseline assertions, completed transitions, fresh recovery and provider qualification; post-deploy transitions also require publication and verification. Read references bind `{proof_hash, evidence_hash}` to native `OperationalProofV1` records. Effect references bind `{operation_id, evidence_hash}` to the exact verified `PlanV2` and its verification artifact. References never carry a caller-selected success boolean. The runtime authenticates stored evidence and checks scope, catalog, build, credential generation, outcome and time. Full-export references additionally require their native governed execution binding and exact database input; recovery expires after 600 seconds.

An optional `observations` declaration binds `baseline` and `terminal` to existing native workspace D1 read capability IDs and committed inventory `Source` identities. Declarations without these bindings remain blocked. Every query must require exactly one non-null integer `passed=1`, with matching finite allowlist and integer bounds; caller parameters and private output are rejected. Runtime intake revalidates all native results and joins the read call, inventory, full source contract, repository, account, database, profile, credential generation, catalog and build. Current baseline observations must follow the original observed baseline and be at most 600 seconds old; typed completed terminal observations must follow their exact atomic commit and precede the application verification derived from them. Identical adjacent boundary inventories may be shared without merging different state predicates. These observations are not an atomic fence or row-preservation proof. Generic schema reads cannot become application preservation assertions, and a verified unrelated plan cannot become executor atomicity qualification. Runtime version 3 remains closed. Version 4 admits an exact native target only after all typed source, assurance, qualification and lineage joins pass. Publication receipt binding resolves as described below. The registered provider capability remains blocked pending isolated provider qualification and separate activation; changing adapter status alone cannot satisfy those gates. The legacy verifier cannot certify V3.

Publication intake requires the verified deploy effect, or a verified upload followed by its exact version promotion. `PublicationRef.upload` is required for promotion; `verification`, `version` and `settings` reference fresh native deployment-list, version-detail and settings reads. The join binds the migration repository and HEAD, committed configuration or its governed private overlay, Worker name, artifact digest/message, sole active version at 100 percent, and the exact D1 binding in version resources and current settings. The Worker profile and credential generation must agree across its publication and read receipts; they may differ from the D1 migration profile. Fresh recovery must follow all three publication reads. This is control-plane publication evidence, not application runtime acceptance or a lock against a later external deployment.

A qualified future effect must enforce migration-relevant preconditions atomically and preserve or correctly transform all eligible data committed before execution. Compatible writes after a recovery snapshot are allowed. An export is recovery evidence, not a compare-and-swap precondition. Native file-import query unavailability must be disclosed without inventing a duration bound. Local D1 batch tests and upstream import behavior are separate evidence classes from actual remote envelope execution.

## Typed runtime intake version 4

Compiler revision `workspace-d1-envelope-v3.4` adds an optional source-owned
`assurance` declaration. Its absence preserves the existing V3 intake; runtime
version 4 requires an explicit declaration. V1/V2 and their full-integrity and
old-Worker requirements are unchanged. Runtime version 3 retains its existing
closed boundary. No public provider adapter or assurance approval command is
enabled by this source preparation.

The strict `RuntimeBindingV4` separates source-bound transport qualification,
atomic execution records, boundary predicates, storage diagnostics and policy
decisions. Unknown fields and generic success-bearing JSON reject. Qualification
must use aggregate schema 2 and kind
`workspace_d1_transition_qualification_v2`, with the complete ten-case matrix:
success, migration failure, preservation-predicate failure, ledger
failure, cleanup failure, concurrent population preservation, interrupted
response, full-scan access path, exact schema format and performance bound.
Every child re-resolves its native plan, authenticated verification evidence,
atomic checkpoint chain and temporally bracketing synthetic observations.
Production database IDs cannot be used as synthetic qualification targets.
The local qualification/population producers are registered through the native proof capability;
existing generic import, legacy Wrangler or unrelated Verified plans cannot
stand in for these records. Matrix presence alone is not remote qualification.

Each completed transition must join its own original baseline, predecessor,
source/envelope/execution identities, assurance identity and qualification.
The exact native plan must reference the apply artifact containing that atomic
execution record. The existing terminal `passed=1` inventory is still required
after atomic commit and authenticated by its typed application verification. A different target's qualification cannot substitute
for an earlier transition's qualification.

`cfctl-cloudflare::d1_transition` implements one-dispatch orchestration. It
validates the complete execution byte digest, durably publishes Prepared and
DispatchIntent before calling a transport once, then persists the terminal
checkpoint. Loss of a response, cancellation after intent, malformed terminal
evidence or failure to persist a terminal checkpoint cannot authorize replay.
Reconciliation accepts a separately authenticated provider disposition and
never resends SQL. A pending or ambiguous effect remains held. This orchestration
has a native file-import adapter routed only for exact consumed V4 plans that reuses the existing
presigned-URL, strong ETag and nested response validators. It requires a consumed,
boundary-attempted exact approved plan, sends the complete immutable bytes once,
uses no transport retries, durably retains private bookmark resume identity,
and bounds requests, response size and its observation window. A separately
approved poll-only continuation cannot init, upload or ingest. Provider errors
remain uncertain until the authenticated native error and complete synthetic
before/after population prove zero delta; they do not directly produce rollback
success. Native qualification and population producers are available locally. Policy activation and rollback reconciliation remain unregistered. Population hashes are
recomputed from authenticated native read results, and successful cases require
the reviewed exact synthetic final-state oracle. Persistence uses the existing
authenticated evidence store and owned private file sink. Provider status and
rollback semantics must still be qualified before production wiring. The source tests exercise failure
and interruption boundaries with synthetic callbacks; they are not provider
atomicity evidence.

## Local native proof production

`cfctl call workspace-d1-transition-produce-proof --body-stdin --json < request.json`
uses the existing authenticated local evidence store and cached catalog. Its
closed request has one `action`: `application`, `population`, `case`, `writer`,
`poll`, or `aggregate`. It accepts no caller verdict, SQL, file path, profile
override or provider selector. Every reference is authenticated again against
the registered committed source, native plan, catalog, build and credential
generation metadata. It never opens a credential or sends a provider request.
Population returns both hashes in `proof_reference`; other actions return the
content-addressed typed evidence hash.

Application requests contain `operation_id`, `terminal_assertions` and
`diagnostic`. Successful verification closes only that pending new native
operation, after joining its approved plan, original V4 admission, immutable
atomic apply record, exact post-commit predicates and assurance diagnostic.
The result reports `plan_status_changed=true`. Missing or substituted receipts
cannot close a plan. Legacy import operations, including a consumed uncertain
operation, cannot acquire this proof or be replayed through this command.
Case, writer and poll actions likewise bind verification to their exact pending
plan journal. A proved rollback retains `RectificationRequired` status. Within
one admission, immutable completed application receipts are authenticated once
and memoized, keeping prefix validation bounded without skipping source or
lineage checks.

The executor publishes a create-only private operation claim before transport,
then authenticated checkpoints and private progress. It imports the complete
execution file without SQL splitting, comment removal or whitespace rewriting.
A failed recording step preserves the claim and returns a pending rectification
result with `no_replay=true`; inability to persist that disposition is disclosed.
A commit remains pending until the application producer verifies its reads.
These local implementations and tests do not establish D1 failure atomicity,
enable a blocked qualification role, activate a managed assurance policy, install
the CLI, authorize credentials, or approve provider effects.

## Managed-D1 assurance proposal version 1

The full mode is `full_integrity_v1`, with a separately declared exact full
diagnostic. The proposed alternative is `managed_d1_application_v1`. The latter
requires a committed `ManagedPolicyV1` source binding the release ID, account,
database, manifest-selected target sequence and immutable migration digest.
Its accepted unobserved properties are exactly global index consistency and
global uniqueness storage consistency. It requires every cumulative control:
primary quick check, exact schema, full-scan typed population preservation,
foreign-key checking, atomic failure rollback, target-once ledger and final
scratch cleanup. Omitting or duplicating a control, changing scope, or selecting
an unknown mode rejects at source compilation.

This is an explicit change in assurance, not a full database certificate. The
source proposal does not record human acceptance. V4 requires an authenticated,
explicitly approved policy decision for the exact compiled identity and policy
bytes. The decision producer requires the exact approved, consumed native policy plan;
no producer/activation path is registered in this change;
therefore managed mode remains held even if local parsing succeeds. Policy
acceptance would not approve installation, a provider trial, a production plan,
another target or a later release.

Storage diagnostics have their own native proof join. Managed mode permits only
the complete no-argument `PRAGMA quick_check;` with exactly one non-null text
`quick_check=ok` row; full mode requires its separately bound full diagnostic.
Neither can replace an ordinary integer boundary predicate. Private diagnostics
must match their authenticated native publication path, hash and byte length,
owned mode-0700/0600 custody, complete source contract, build/catalog/profile/
credential generation, primary response, exact output and freshness chronology.
Private metadata capture alone does not qualify a diagnostic. The tested
provider rejection of a full diagnostic remains a held requirement; this
proposal does not generalize that rejection to every possible full-check API.

The synthetic tests exercise the frozen manifest schedule, all target declarations, original byte preservation, rejected gaps/prerequisites/source drift, receipt provenance and blocked execution. They do not qualify any application's actual migration or authorize provider actions.

Qualification binds each exact fixture digest and byte length to the reviewed
synthetic case. The executor checks both before dispatch. The performance case
must execute at least the compiled execution length, and the aggregate maximum
must equal a bound executed fixture size. Size coverage does not prove equivalent
workload: synthetic topology/population applicability to the production envelope
remains an explicit review and qualification requirement. A minimal complete
synthetic fixture cannot certify a larger private production topology.

Rollback reconciliation pins the original authenticated provider-error artifact
and bookmark. Before/after population reads bracket that error; they do not need
to bracket the later artifact that records reconciliation. Import resume and
terminal bookmarks are retained only in the existing private file sink; public
evidence carries their hashes and file metadata.

Before and after populations bind separate source inventories and explicit
receipt phases. A successful migration can therefore observe newly created
alias/event tables only afterward, while retaining complete old rows in both
captures. Failure cases require identical inventory declarations on both sides
so zero-delta comparisons use the same query/hash domain. Neither a missing table
nor an unobserved new-table population is represented as an empty successful read.

Historical source ledgers preserve the canonical optional `sequence`,
`migration_class` and `notes` fields. When present, sequence/class must agree
with the manifest identity and notes must be nonempty text. Unknown fields and
contradictory metadata reject. These source records do not establish installed
D1 history.

Case-specific admission preparation retains raw native import error responses
only in the existing private progress sink, with a bounded hash/size/path
publication. Exact structured sentinel messages can identify an isolated fault;
SQL echoes, substrings and unknown provider wrapping cannot. Capturing a private
error does not prove rollback, and all full-population and checkpoint joins remain
required. This preparation does not enable a public qualification executor.

The unregistered qualification source now routes each of the ten cases through
its own evidence requirements. Failure cases require the exact approved sentinel
in a recognized structured native error plus complete zero-delta population
proof. The writer case requires a distinct approved committed writer, a complete
post-writer population, and baseline/writer/read/capture chronology. The
interruption case requires the exact approved poll-only continuation of an
authenticated uncertain checkpoint. Performance bounds use authenticated apply
checkpoint times, rather than caller timing fields. The full-scan case accepts
only the narrow direct-table `NOT INDEXED` population grammar without filtering
or sampling; this validates executed SQL source, not an observed provider query
plan or global index integrity. The schema-format case requires the exact raw
application `sqlite_schema` projection and native final-state oracle.

Preservation-predicate failure is a distinct required case. Its approved fixture
must cause an original preservation predicate to reject a changed captured row;
an unconditional migration-stage fault does not establish this coverage. The
native verifier requires the exact source-bound structured error marker and
complete same-inventory zero-delta proof, with the same authenticated checkpoint
and original apply-artifact joins as other failures. Aggregate schema 1 and a
nine-case matrix cannot satisfy schema 2. Local qualification requires affected
and canonical verification bound to the exact current source inputs. An earlier
nine-case canonical pass cannot qualify the ten-case extension, and local source
verification does not establish authenticated provider case results.

Separate local producers prepare child, writer and poll verification evidence
from their exact consumed approved plans and apply artifacts. They cannot dispatch,
approve or register an operation. Rollback reconciliation produces an apply
record; only the common case verifier can produce its post-change verification.
Bound inventory and writer inputs must also match their committed Git blobs,
current repository revision and local bytes. These later additions are source
preparation. The affected native transition tests pass, including source-drift,
case-specific verification and evidence-lineage checks. The revised synthetic
companion also passes native inventory validation. These are local proofs;
earlier full or partial verifier results do not qualify changed inputs, and
provider execution remains unqualified. Public V3 execution remains disabled.

Checkpoint lineage and stored evidence have separate hash domains. Lineage uses
compact canonical values; authenticated evidence storage hashes its immutable
pretty-printed redacted body. An execution record therefore binds an ordered,
unique `checkpoint_evidence_hashes` vector alongside its checkpoints. The native
consumer loads each exact stored artifact, checks its apply class and body, and
derives chronology from its authenticated descriptor. A canonical lineage hash
cannot substitute for the storage reference.

Post-change execution and poll artifacts use closed verification wrappers with
distinct kinds and an exact `apply_evidence_hash`. Their payload must match the
original plan-bound apply record or transport receipt. This preserves the
storage rule that one immutable content body cannot acquire conflicting evidence
classes. Qualification, writer, poll and completed-lineage consumers join both
identities; generic verification flags and bare apply bodies cannot substitute.
Native regression tests now cover these hash-domain and class-identity joins.
The qualification, writer, poll, population and policy routes remain
unregistered; passing local tests does not create callable operations or admit
their resource, permission, cost or approval contracts.

### Committed synthetic source binding

The source-only qualification binder reads committed
`.cfctl/operations/d1-transition-qualification.toml` with schema version 1 and
contract `workspace_d1_transition_qualification_v1`. This is a separate contract
from the schema-2 qualification evidence aggregate. Every derived capability
is explicitly Blocked: source inspection does not admit a native lifecycle.

The pack selects one existing typed transition operation and exactly nine unique
role declarations: create, seed, execute, writer, poll, cleanup, population,
aggregate and policy. It freezes exactly ten distinct case/resource names,
maximum_live_databases = 1, maximum_database_lifetimes = 10 and
resets_allowed = false. Each case binds committed seed and execution SQL,
before/after inventories and full expected-population oracles through relative
paths, SHA-256 digests and Git blob identities. Fault cases require the same
before/after inventory and semantic population digest plus their exact sentinel;
performance and concurrent-writer inputs belong only to their respective cases.
All observation references select the declared population role. The referenced
transition must already declare observations and explicit assurance; this does
not accept a managed-assurance policy or qualify its omitted properties.

Inspection reads committed bytes while preserving dirty app work. Execution-mode
source loading additionally requires clean source and unchanged local bytes.
Oracle binding checks the complete ordered query population, query hashes,
column names, row bounds and canonical semantic digest. Native SQL validation,
cell types, observed provider results and verification remain separate checks.

Resource UUIDs and approved operation/evidence references are deliberately absent
from this committed source. A future executor must derive them from exact
approved create receipts without changing the shared source revision between
the ten sequential lifetimes. Existing production read packs pin a database UUID
and therefore cannot be rebound after each create without invalidating that
shared revision. Prepared native synthetic read materialization still requires qualification and
public lifecycle admission. Seeded-resource cleanup also requires its own exact created
resource and terminal-evidence admission; empty-create compensation cannot
authorize deleting a seeded database. No provider execution or approval follows
from this binder, and production transition execution remains disabled.


### Receipt-derived synthetic resource source preparation

The additive resource source contract joins each frozen case name and transition
identity to an exact approved, verified native create plan and its authenticated
apply/readback UUID. It rejects the production UUID, account or credential drift,
unreviewed names, missing approval, failed creation and mismatched readback. The
workspace materializer rebinds the current clean committed qualification pack and
projects the selected before/after/post-writer inventory for that derived UUID;
it changes neither the pack nor the source revision. The CLI preparation path
also invokes the existing native read compiler against that inventory.

A proposed seeded cleanup target separately joins the create, distinct approved
source-bound seed and terminal verified case, including exact source byte counts,
terminal population/oracle and native chronology. It grants no deletion or absence
claim and does not change empty-create compensation. These preparation functions
remain unregistered. The prepared native synthetic read producer now derives the internal inventory
contract from that receipt, rechecks source/create/profile before each query,
uses the existing Executor, and persists only compiler-qualified results with the
closed resource/phase binding. Population consumers reconstruct the same source
and phase before accepting its semantic digest; legacy fixed-UUID reads remain
compatible. Public dispatch stays closed. Sequential lifetime admission, seed/cleanup planners,
executors/verifiers, fresh absence checks and cleanup failure reconciliation are
not implemented by this source delta. All nine public derived roles remain
Blocked, and costs, resource permissions and explicit operation approvals still
need their own reviewed admission. This delta requires fresh affected and full
native qualification; the frozen47-input proof covers only its earlier source.
