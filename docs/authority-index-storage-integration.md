# Counted-index storage and production integration

## Status

This is a source implementation contract, not installed storage or execution
evidence. The current tree has a pure [range reconstructor](authority-index-range.md),
fixed projection codecs, an actual [primary-row join](authority-index-primary-join.md)
and a standalone bounded SQL frontier reader. The reader reconstructs against a
supplied root; it does not authenticate that root or its currentness. There is
still no installed counted-index schema, authenticated population, all-writer
maintenance or independently admitted current index/primary root pair. The
planner still rejects complete-index queries before business/proof SQL. Existing
startup and verification gates remain closed.

The [all-profile mutation evaluator](authority-index-mutation.md) now also
derives counted before/after roots from the actual primary engine's verified
OLD/NEW snapshots. It fixes member-event revision semantics and shared component
budgets, but is not installed SQL maintenance or executor root-vector admission.
The [operation-bound transition document](authority-counted-root-transition.md)
now packages that genuine result and recomputes claimed write transitions; it
does not yet include read-only or complete-query counted dependencies.
Source renderers now also define native PostgreSQL counted hashes and fixed row
projections, fresh dedicated storage DDL, and normalized per-profile/all-profile
[SQL maintenance](authority-counted-sql-maintenance.md). Their real-engine fixtures are
authored for later prepared verification; neither the SQL nor the fixtures have
been executed or installed into the production schema.

The existing `policy_authority_secondary_index_heads` declaration is metadata,
not an implementation of the counted profile. Its relation/index names, column
digest, root, revision, count and optional high-water fields neither store a
radix frontier nor establish how that frontier was maintained. The existing
`exact_page_receipt` checks a closed receipt and its digests; it does not invoke
the counted-range reconstructor. Neither API may be relabeled as complete-range
proof without the coordinated changes below.

## Source-owned storage shape

The standalone reader fixes two transport relations in `serverware_metadata`;
it accepts no caller namespace or table name:

- `policy_authority_counted_index_leaves`: `index_id`, `projection_digest`,
  `index_key`, `primary_id`, `primary_key_digest`, `primary_row_digest`,
  `index_revision`.
- `policy_authority_counted_index_nodes`: `index_id`, `projection_digest`,
  `depth`, `path_prefix`, `node_digest`, `subtree_count`, `index_revision`.

The expected scalar types are exact PostgreSQL `text`, `int4` for node depth,
and `int8` for revisions and counts. CASE projections check those types and
bounded text byte lengths or integer ranges before returning values; malformed
values become rejecting NULL sentinels or fail the query. Index keys are 160
lowercase hex digits, digests are canonical 71-byte SHA-256 strings, primary IDs
are exact UTF-8 text of at most 4096 bytes (including the permitted empty ID),
and node prefixes have 1–160 digits matching their depth. Positive record
revisions may not exceed the supplied index revision. The reader additionally
checks each primary ID's BusinessKey/v1 digest and the index-key suffix. This
authenticates lookup material only relative to the reconstructed counted root;
primary membership and semantic projection still require the real row join.

These are implemented acquisition shapes, not installed catalog/ACL admission.
The SQL comparisons explicitly use `C` collation; installed storage must still
admit the matching column/index ordering and constraints below.

The [fresh PostgreSQL storage component](../serverware/authority_store/counted_store_sql.py)
uses a dedicated
`policy_authority_counted_index_heads` relation with `index_id`, `table_name`,
`counted_profile`, `projection_digest`, `projection_manifest_digest`,
`index_revision`, `root_digest` and `leaf_count`. This is a counted checkpoint
descriptor; the separately versioned root vector must bind it to the actual
primary checkpoint. Merely storing both roots does not authenticate either.

The schema must bind the exact counted profile, projection descriptor and
projection manifest. The eleven source profiles cover six base relations:
credentials and trust publications have three profiles each, challenges have
two, and sessions, grants and control-plane approvals have one each. No caller
supplies a projection program, table name or SQL predicate.

A complete storage contract also needs these logical records and constraints
fixed before installation:

- A head for each source index: profile/descriptor identity, counted root digest,
  nonnegative count, revision and a defined association with the base relation's
  primary checkpoint. A same-database pair is not independent currentness.
- Sparse positive-count nodes keyed by index identity, depth and lowercase
  hexadecimal prefix. Depth is at most 160; prefix length equals depth. Counts
  fit signed64 and cannot exceed the number of fixed-key slots below the prefix.
  Missing children mean the profile's canonical empty node, not a zero-count
  explicit child. The empty-root storage convention must be explicit.
- Leaves keyed by index identity and an exact 160-nibble key, carrying BusinessKey/v1
  and AuthenticatedRow/v1 commitments and bounded source primary-key material.
  All eleven current profiles use the exact `id` text key. A digest alone cannot
  recover that key to select the actual primary row. Stored key material is
  untrusted lookup input until its canonical key digest, source columns and
  genuine primary membership have been checked.

The existing metadata head requires `revision > 0`, while the pure anchor admits
revision zero only for an empty count. A new installed contract must choose its
genesis revision explicitly; it cannot silently reinterpret either convention.

The dedicated fresh-store contract chooses revision zero only for an empty
count and the source profile's exact empty-root digest. Empty heads at later
revisions are also valid, such as after deleting the last member. No DDL default
or insert manufactures a head. The source-fixed profile/manifest constraints
admit all eleven exact index/table/descriptor combinations. Leaves use
`(index_id, index_key)` as their primary key and uniquely constrain
`(index_id, primary_key_digest)`; the potentially 4096-byte primary ID is not a
B-tree index key. Leaves and nodes bind their profile to a head through a
nondeferrable foreign key. All stored text uses `C` collation.

These scalar constraints do not prove that stored primary IDs hash to their
commitments, that nodes match leaves, that record revisions do not exceed their
head, or that the index has complete authenticated population. Those cross-row
and cryptographic invariants remain maintenance/admission obligations. No
standalone DDL renderer installs its tables into the production schema.

Use byte ordering or an explicitly admitted `C` collation for hexadecimal keys
and prefixes, with a matching unique range index. Constraints and catalog
admission must close types, lengths, digest syntax, key uniqueness, revision
rules, owners, ACLs, triggers and installed function definitions. SQL transport
must additionally project overlimit or malformed fields to a rejecting sentinel
before fetching them. A `WHERE` clause must not hide malformed matching records.
Transport bounds do not prove backend allocation or query-plan cost bounds.

The [native counted hash renderer](../serverware/authority_store/counted_hash_sql.py)
now implements the exact empty, leaf and branch shapes: eight, ten and forty
payload frames, plus the length-framed domain. Its separate helper admits only
those three domains/shapes. The primary helper remains limited to eight frames
and its primary-tree domains remain unchanged. Source-fixed profile lookup,
prefix/key/digest validation, exact sixteen paired child slots, fixed-key
capacity and signed64 overflow checks precede the relevant counted hashes.

The [native row projection renderer](../serverware/authority_store/counted_projection_sql.py)
derives all eleven fixed projections from supplied full rows, including the
actual ASCII-wire BusinessKey/v1 and UTF-8 AuthenticatedRow/v1 commitments. It
validates every referenced field before membership, measures bounded lossless
full-row JSON, and uses the unchanged UTF-8 tree serializer for the shallow
partition map. Exact UTC calendar/microsecond validation and a signed-bit-flip
ordering codec avoid session-timezone dependence or floating-point integer
ordering. Nonmembers return no projected leaf, not an unvalidated row.

These are uninstalled invoker functions, not trusted trigger inputs or a schema
admission. PostgreSQL JSONB has already discarded duplicate fields and normalized
some number spellings; the functions do not establish raw-input validity,
parser/detoast allocation bounds, primary membership or currentness. Real SQL
and Python parity, native date/Unicode behavior and negative cases remain
unexecuted. Their installation still requires the coordinated contract below.

## Bounded frontier production

[`read_complete_frontier`](../serverware/authority_index_reader.py) now accepts
an actual `CompleteIndexQuery`, supplied counted root/revision, cursor and trace.
It returns immutable `AcquiredIndexFrontier` observation data: the revalidated
query, root, interval, actual frontier, ordered primary lookup IDs and metrics.
It invokes the real range reconstructor before returning; no caller-supplied
successful verifier result or callback is accepted. The current declaration
family admits at most 32 inside leaves. This component does not bind the query
to the consumer's actual operation arguments/time, select or authenticate a
head, acquire primary rows, invoke the primary join, or authorize a kernel.

The source query primitive selects an admitted index and a closed selector.
The actual projection codec derives `[lower, upper)`; the implemented reader
accepts no independently caller-chosen interval or resource limits. Future
deferred selector fields must pass the existing staged primary verifier before
influencing these reads.

Production integration must capture the source-admitted index head and primary
roots in the same planning transaction before frontier reads. If the existing
secondary-head relation is used, verify that head row's genuine primary proof
too, under its own relation's captured root; the base-row join does not perform
this extra authentication.
Retain the exact head/profile/root association for executor lock/CAS admission.
None of these same-database associations replaces an independent checkpoint.

The implemented reader acquires two different kinds of evidence:

1. Read all leaves inside the derived interval in exact key order, with a source
   leaf ceiling and `LIMIT ceiling + 1`. Any overflow rejects the whole complete
   query. A truncated result is not a complete range or an authorized page.
2. Compute the canonical prefix cover of the interval's complement from the
   interval bounds alone. Point-read those outside prefixes, admitting each
   returned positive subtree as an opaque frontier entry and rejecting a stored
   zero count. Missing nodes are handled separately. Do not scan all leaves
   outside the interval, and do not accept producer-selected opaque prefixes
   that intersect it.

For a contiguous 160-nibble interval, its two complement sides require at most
`2 * 160 * 15 = 4800` prefix slots. An empty interval can use the sixteen
depth-one slots; a whole-keyspace interval has no outside prefixes. An opaque
root is always forbidden. Chunking at most 256 exact node identities per SQL
statement gives at most 19 outside-node reads plus one leaf-range read. The
reader implements this fixed bound and emits one trace entry per physical
SELECT under `serverware.policyAuthorityCountedIndexRead/v1`. That profile is
not admitted by the production planner's trace contract.

Each node query uses bound identities, exact index/depth/prefix joins, a bounded
`LIMIT requested + 1`, and a bounded fetch. Reject duplicate, unexpected, crossed,
malformed or future-revision results. A missing requested node is an empty
candidate only: the actual reconstruction against the separately admitted root
must still succeed. Missing populated evidence must change that root and deny.
No response filter may convert corruption into successful absence.

The reader merges inside leaves and outside opaque subtrees into a sorted,
prefix-free frontier and performs actual reconstruction. Its source-derived
limits are `4800 + maximum_rows` entries, `1 + 160 * maximum_rows + 320`
opened nodes, and `16 * opened_limit + maximum_rows` reconstruction hashes.
At the current 32-leaf declaration ceiling these are 4832, 5441 and 87088,
respectively, within the pure reconstructor's larger component ceilings. These
are conservative source bounds, not measured execution results.

Returned scalar accounting has a separate 4 MiB cap: record kind followed by
the fixed-order column values, each UTF-8 encoded (integers in decimal) with an
eight-byte length prefix. It excludes PostgreSQL wire framing, driver/parser
memory, outbound parameters and database execution cost. Reconstruction also
enforces its own 4 MiB scalar-framed input budget; neither metric substitutes
for the other. Reader hash metrics charge four context hashes, one BusinessKey
hash per inside leaf and the actual reconstructor hash count. Missing nodes
never bypass that reconstruction.

Fetch the exact primary rows named by the acquired leaf key material using
bounded exact-key reads, not by trusting the original SQL predicate result.
Acquire genuine primary proofs and call the actual joined verifier; its
bijective comparison binds each complete-range leaf to the same owned full row
that passed primary verification and to its rederived source projection.
Query-local wrappers must retain `contractSelector = None`; legitimate selector
metadata on the global selected union remains a distinct, checked view.

## Whole-operation accounting and protocol

The per-query SQL bound excludes head admission, primary-row acquisition and
primary proofs. Count those actual reads separately. With a bounded bulk
primary-row fetch and the existing business proof producer, the latter proofs
cost at most `5N` reads; this is not permission to hide multiple queries behind
one trace entry. Every physical read needs a closed source trace identity.

Multiple complete queries must share operation-level ceilings for SQL calls,
returned/transferred bytes, frontier entries, opened nodes, hash work, primary
vectors/slots and retained evidence. Clamp remaining limits before each phase.
The join's standalone component allowance is not a new whole-plan allowance:
the outer 64 MiB plan cap, existing business/framework row distinction and exact
global-counter singleton block remain separate. Do not silently raise 4096 or
charge new index reads as the existing primary batch profile.

Current query records are ephemeral observations. Production integration needs
a closed versioned query/evidence transport binding the source query identity,
selector, profile, root pair, ordered members, empty result and actual frontier.
It must be retained before kernel use and independently admitted by Python and
SQL consumers. The exactly nine-frame Snapshot/v3 and current primary Proof/v3
must not acquire additional fields or completeness meaning without coordinated
versioning. Preserve historical replay against its original before evidence;
do not reinterpret it using current mutable heads.

The [independent current-root witness design](authority-current-root-witness-integration.md)
maps the separate enrollment, full-vector, pending-fence and uncertain-commit
requirements. Existing result-bound replay receipts are not root currentness.
Its proposed protected untracked framework marker avoids a circular dependency
between a pending decision and the application after-root; no new authority or
protocol is activated by that design.

## All-writer maintenance and head effects

An index leaf commits the **full** primary row digest. Maintenance cannot run
only when indexed columns change. For example, a credential sign-count update
changes all its member index leaves even if its user, credential identifier and
trust-membership fields stay equal. OLD/NEW projection must handle membership
entry/exit, ordering/partition moves, full-row updates, deletion and permitted
primary-key changes, with overflow and collision checks before publication.

The existing primary trigger is a useful all-row-DML attachment point: it runs
after INSERT/UPDATE/DELETE, locks the table root, applies the leaf and ancestors,
increments its revision and records the primary root transition. The counted
tree needs its own matching fixed 160-level logic, source projection parity and
deterministic lock order. It cannot share primary nodes or treat empty hashes
as prefix-independent. Dedicated store writes must not recursively index their
own maintenance records.

The shared primary trigger normalizes a primary-key-changing UPDATE into a
DELETE and INSERT. Counted maintenance must use those same two primary events
and their revision effects; an unchanged-primary-key partition move remains one
event. The pure evaluator still rejects a key-changing UPDATE. This is the
required normalization for a future hook, not an installed trigger change.

The native component now implements the normalized event and actual path
maintenance below, without attaching that hook or admitting caller-provided
JSONB as authenticated images. Its 18 native fixture methods remain unrun; the
bounded algorithm and its limitations are detailed in the
[SQL maintenance reference](authority-counted-sql-maintenance.md).

A normalized SQL event must lock the complete fixed source-head set in index-ID
byte order before processing any profile, including when both images are
nonmembers. Missing heads deny; they never trigger genesis. Before persistent
counted writes, verify exact OLD leaves, absence for newly inserted target
paths, immediate untouched sibling commitments and the reconstructed BEFORE
root/count. Also compare stored nodes on opened paths with their reconstructed
BEFORE values: silently
overwriting a corrupt redundant node is not an admitted repair. With no target
paths, still fold the root from its sixteen depth-one children. Opaque off-path
subtrees remain relative commitments, not an audit of their interiors.

Per-event bounds do not constrain a multirow transaction. Existing bulk writers
need explicit operation-wide accounting; caller-controlled counters or session
settings cannot authorize a reset. SQL projection also performs hashes that the
pure combined evaluator reuses from primary verification, so native accounting
must charge its own actual work or a conservative source-fixed upper bound.
The existing executor/root and direct-writer/row lock order is not yet proven
deadlock-free; a source-level ordering rule is not concurrency test evidence.

Maintenance must cover every supported writer, not just the four missing
WebAuthn kernels. Existing source contains challenge expiry/pruning, recovery,
bulk revocation and browser-session lifecycle writers. Some are already behind
authority-only DML permissions; OIDC session writes are intentionally not in the
ordinary runtime readonly inventory. Do not silently revoke that path, grant it
generic index writes, or claim planner-only maintenance covers it. Each writer
needs the same guarded atomic maintenance path or an explicitly coordinated
replacement before index activation. TRUNCATE, trigger disabling, replication
trigger modes and privileged migration writes also need explicit exclusion or
an admitted maintenance procedure.

The existing secondary-head relation is itself tracked by the primary tree.
Updating a row there invokes primary authentication and changes that relation's
primary root, revision history and leaf commitment. It is not an invisible
cache write. If it stores the new counted heads, affected operations must select
and prove those old head rows, predict their exact new values and account for
their primary root effects, mutation/work bounds and source permissions.

The current implementation direction is a dedicated counted-head vector with
explicitly versioned before/after admission, rather than automatic writes to
the primary-tracked secondary-head relation. The pure mutation evaluator fixes
the expected effects, not their SQL installation. Every counted head must be
bound to the snapshot, root locks/CAS, receipts and independent checkpoint;
otherwise separate storage is an unauthenticated shortcut.

Reusing the primary-tracked relation would instead need one deterministic
owner-batch head transition per affected index, admitted and applied exactly
once after its base-row changes. That alternative requires all writers to
participate in a finalization barrier. A trigger must not also update the same
head which a generic mutation template will later apply.
Conversely, per-row trigger-owned head updates require explicit modeling of
every intermediate update and revision increment: the current primary batch
evaluator rejects repeated mutations of one key, and cannot silently represent
them as one final update. Runtime-generated head timestamps likewise cannot
replace precommitted full-row values without changing the predicted root.

`executor_v9` currently locks the declared before roots, executes the exact
mutation list and compares all declared after roots before issuing its receipt.
Preserve that boundary. Expand the source root closure and actual evaluator for
any additional head effects, or use a separately versioned counted-root vector
with equivalent before/after admission. Neither hidden writes nor double apply
may be excused by only checking the final counted root. An operation that treats
the head relation as authorization-only cannot mutate it under the current
unchanged-authorization-root rule.

## Authenticated bootstrap and migration

An absent index head is not permission to create an empty index over populated
data. Existing primary initialization already rejects preserved populated
relations without a signed offline restage. Counted-index installation needs
an equally explicit authenticated population contract, not a startup scan that
trusts its own newly generated digest.

Under a separately admitted offline fence/checkpoint and stable writer lock:

- Enumerate the entire authenticated primary population in bounded complete
  chunks and validate every source-referenced projection field, including
  nonmembers. Existing unrestricted TEXT does not imply the new 4096-byte,
  exact-Unicode, canonical-UTC or signed-integer codec contract.
- Derive every required index member from those same verified full rows. Check
  the reverse direction too: every stored index leaf must have exactly one
  eligible primary source with the exact key and row commitments. Equal counts
  alone do not prove absence of omissions, substitutions or extra leaves.
- Reconstruct counted nodes, counts and heads and their resulting primary-head
  effects. Bind the exact projection/source/schema identities, input roots,
  output roots, total population and resumable-work commitments to installation
  evidence. Reject partial population and accidental reuse of an old profile.
- Commit all storage and authority heads atomically under the admitted fence,
  with independently retained one-use/ancestry evidence. A same-database receipt
  erased with that database is not rollback resistance. Large retained history
  requires bounded offline work, not an unlimited online bootstrap scan.

Any incompatible historical value needs an explicit reviewed migration policy;
do not silently normalize it or rebuild an accepted index when state is absent.
The audit-capacity initializer's signed purposes do not authorize index
installation. Source code and same-database locks cannot manufacture independent
enrollment, current-root authority, trusted expiry time or witness durability.

Activation must also update the actual schema-composition contract. The current
shared schema program is unqualified and serves canonical, scratch and SQLite
paths; a PostgreSQL-only, namespace-qualified fresh renderer cannot simply be
appended with a hardcoded production namespace. Canonical installation and
expected-schema replay need the same admitted PostgreSQL stage, source digest,
function definitions and catalog closure. Fresh-only `CREATE TABLE` must not be
replayed over an existing schema, and `IF NOT EXISTS` is not shape validation.

New stores must enter the exact runtime-readonly and owner-dependency
inventories before the blanket runtime DML grant is narrowed. Planner reads
need separate explicit grants. They must stay out of primary-tracked table and
trigger inventories. Versioned migration inventories, current-schema drift
checks and later initialization backfills also need coordinated changes; a
receipt-only repair cannot authorize new storage or skip uninitialized index
maintenance. None of these activation changes is supplied by the fresh DDL.

## Source seams and verification obligations

Current implementation anchors:

- [`authority_index_reader.py`](../serverware/authority_index_reader.py) and
  [`authority_index_frontier.py`](../serverware/authority_index_frontier.py):
  fixed standalone SQL acquisition, bounded canonical outside identities and
  actual reconstruction relative to a supplied root; no storage installation
  or planner activation.
- [`authority_index_contract.py`](../serverware/authority_index_contract.py),
  [`authority_index_range.py`](../serverware/authority_index_range.py),
  [`authority_index_projection.py`](../serverware/authority_index_projection.py)
  and [`authority_index_join.py`](../serverware/authority_index_join.py): the
  genuine hash, projection, reconstruction and same-owned-row join semantics.
- [`primary_tree_sql.py`](../serverware/authority_store/primary_tree_sql.py):
  existing bounded framing and primary row-trigger mechanics.
- [`counted_hash_sql.py`](../serverware/authority_store/counted_hash_sql.py) and
  [`counted_projection_sql.py`](../serverware/authority_store/counted_projection_sql.py):
  source-fixed native counted hashing and actual row projection definitions;
  no storage, trigger attachment, grants or installed-profile admission.
- [`counted_store_sql.py`](../serverware/authority_store/counted_store_sql.py):
  fresh-only dedicated heads/leaves/nodes DDL with fixed source profiles and
  local constraints; no seed, maintenance, runtime grants or installer changes.
- [`counted_path_sql.py`](../serverware/authority_store/counted_path_sql.py) and
  [`counted_maintenance_sql.py`](../serverware/authority_store/counted_maintenance_sql.py):
  actual bounded before/after reconstruction, persistence and complete-profile
  event dispatch; no installed trigger provenance or current-root authority.
- [`v9_schema_source.py`](../serverware/authority_store/v9_schema_source.py) and
  [`metadata_schema_source.py`](../serverware/authority_store/metadata_schema_source.py):
  existing secondary-head metadata and primary physical stores.
- [`db.py`](../serverware/db.py): tracked-root bootstrap, trigger attachment,
  runtime permissions and legacy writers; [`schema.py`](../serverware/authority_store/schema.py):
  exact schema/function/trigger ownership and source-contract admission.
- [`authority_planner.py`](../serverware/authority_planner.py) and
  [`authority_query_staging.py`](../serverware/authority_query_staging.py):
  transaction-local query acquisition and authenticated deferred sources.
- [`authority_root_transition.py`](../serverware/authority_root_transition.py),
  [`executor_v9.py`](../serverware/authority_store/executor_v9.py) and
  [`root_transition_sql.py`](../serverware/authority_store/root_transition_sql.py):
  exact before roots, predicted mutation effects, locked DML and after-root CAS.

The coordinated source revision must update contracts, complete-schema source,
owner/import/function/trigger inventories, planner/executor permissions, budgets,
transport versions and migration receipts together. Authored coverage should
include real SQL/Python projection/hash parity, omitted/extra/corrupt frontier
records, overlimit results, empty intervals, all writer transition categories,
full-row-only updates, rollback, head exactly-once effects and bootstrap in both
directions. Native verification remains a later frozen, prepared, no-build phase;
this document records no executed test or production installation.

The standalone [frontier fixture](../scripts/test_authority_index_frontier.py)
contains 24 authored, unrun methods using independent integer-prefix tiling and
counted-tree encodings. A deterministic stored-row cursor exercises the actual
reader and reconstructor, including omissions, overflow and changed commitments.
Emitted-SQL assertions and private accounting-boundary checks are supplemental;
they do not execute PostgreSQL or establish its types, collation, query plan,
installed schema, transactional maintenance or independent root authority.
