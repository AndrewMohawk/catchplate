# Counted-index storage and production integration

## Status

This is a source implementation contract, not installed storage or execution
evidence. The current tree has a pure [range reconstructor](authority-index-range.md),
fixed projection codecs and an actual [primary-row join](authority-index-primary-join.md).
It does not yet have counted-index SQL storage, an authenticated population,
all-writer maintenance, a frontier reader, or independently admitted current
index/primary root pairs. Existing startup and verification gates remain closed.

The existing `policy_authority_secondary_index_heads` declaration is metadata,
not an implementation of the counted profile. Its relation/index names, column
digest, root, revision, count and optional high-water fields neither store a
radix frontier nor establish how that frontier was maintained. The existing
`exact_page_receipt` checks a closed receipt and its digests; it does not invoke
the counted-range reconstructor. Neither API may be relabeled as complete-range
proof without the coordinated changes below.

## Source-owned storage shape

The schema must bind the exact counted profile, projection descriptor and
projection manifest. The eleven source profiles cover six base relations:
credentials and trust publications have three profiles each, challenges have
two, and sessions, grants and control-plane approvals have one each. No caller
supplies a projection program, table name or SQL predicate.

A minimal storage contract needs these logical records, with exact names and
constraints fixed before installation:

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

Use byte ordering or an explicitly admitted `C` collation for hexadecimal keys
and prefixes, with a matching unique range index. Constraints and catalog
admission must close types, lengths, digest syntax, key uniqueness, revision
rules, owners, ACLs, triggers and installed function definitions. SQL transport
must additionally project overlimit or malformed fields to a rejecting sentinel
before fetching them. A `WHERE` clause must not hide malformed matching records.
Transport bounds do not prove backend allocation or query-plan cost bounds.

The primary SQL hash helper cannot simply be reused for every counted hash:
`primary_tree_sql.framed_digest_function_sql` admits at most eight payload
frames. Counted empty, leaf and branch hashing respectively need eight, ten
and forty payload frames, plus the length-framed domain. A separate closed
counted-index renderer should implement those exact purpose-specific shapes
and bounds. Do not enlarge the primary helper's contract or substitute its
different primary-tree hash domains. Projection partition JSON must also match
the fixed UTF-8 codec, not merely an approximately equivalent JSONB spelling.

## Bounded frontier production

The source query primitive selects an admitted index and a closed selector.
The actual projection codec derives `[lower, upper)`; the producer must not
accept independently caller-chosen interval bounds. Deferred selector fields
must pass the existing staged primary verifier before influencing these reads.

Capture the source-admitted index head and primary roots in the same planning
transaction before frontier reads. If the existing secondary-head relation is
used, verify that head row's genuine primary proof too, under its own relation's
captured root; the base-row join does not perform this extra authentication.
Retain the exact head/profile/root association for executor lock/CAS admission.
None of these same-database associations replaces an independent checkpoint.

Acquire two different kinds of evidence:

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
statement gives at most 19 outside-node reads plus one leaf-range read. This is
a proposed source profile, not an existing registered SQL trace contract.

Each node query uses bound identities, exact index/depth/prefix joins, a bounded
`LIMIT requested + 1`, and a bounded fetch. Reject duplicate, unexpected, crossed,
malformed or future-revision results. A missing requested node is an empty
candidate only: the actual reconstruction against the separately admitted root
must still succeed. Missing populated evidence must change that root and deny.
No response filter may convert corruption into successful absence.

Merge inside leaves and outside opaque subtrees into a sorted, unique,
prefix-free frontier. At 256 returned leaves, the conservative entry ceiling is
5056, below the pure component's 8192 ceiling. A conservative proper-ancestor
bound is `1 + 160N + 320`, below 65536 at `N <= 256`; charging at most 16 hashes
per opened branch plus one per leaf is also below the component's 1048576 hash
ceiling. These are source upper bounds, not measured execution results. The
actual scalar-framed byte accounting and 4 MiB range ceiling remain mandatory.

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

Choose the update schedule before implementing DDL or triggers. The preferred
bounded owner-batch shape is one deterministic final head transition per
affected index, admitted and applied exactly once after its base-row changes.
That requires all writers to participate in that barrier. A trigger must not
also update the same head which a generic mutation template will later apply.
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

## Source seams and verification obligations

Current implementation anchors:

- [`authority_index_contract.py`](../serverware/authority_index_contract.py),
  [`authority_index_range.py`](../serverware/authority_index_range.py),
  [`authority_index_projection.py`](../serverware/authority_index_projection.py)
  and [`authority_index_join.py`](../serverware/authority_index_join.py): the
  genuine hash, projection, reconstruction and same-owned-row join semantics.
- [`primary_tree_sql.py`](../serverware/authority_store/primary_tree_sql.py):
  existing bounded framing and primary row-trigger mechanics.
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
