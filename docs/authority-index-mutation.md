# Primary and counted-index mutation evaluation

## Implemented boundary

The source now has a pure combined evaluator,
[`evaluate_indexed_primary_batch`](../serverware/authority_indexed_mutation.py).
It genuinely verifies a primary mutation batch, derives every affected fixed
index projection from the same owned OLD/NEW images, and reconstructs the
counted before and after roots. Its output is conditional on the supplied
table contracts and root descriptors. It authenticates neither currentness nor
operation intent, and is not evidence that an entire historical index was
correctly populated.

This is source implementation, not installation or execution evidence. There
is no installed counted SQL maintenance, head schedule, Snapshot/v4 protocol,
planner/executor activation, authenticated bootstrap or independent root
authority supplied by this component. Existing gates remain closed. The
standalone [range reader](authority-index-storage-integration.md) does not fill
these gaps or automatically produce the mutation frontier described below.
The separate [write-proof SQL producer](authority-index-mutation-reader.md)
now acquires that exact evidence from verified primary OLD/NEW images and
invokes the actual sparse folds, without admitting production trace/currentness.

The [operation-bound write-transition document](authority-counted-root-transition.md)
now invokes this evaluator once with source-owned contracts and packaging
reserves, retaining its actual primary result and exact counted before/after
heads. It remains write-effects-only, not full query/root-vector admission.
The [complete read/write composer](authority-complete-read-write.md) separately
uses this actual evaluator with the genuine complete-query phases and one
shared budget, computing the full read/write union without accepting a prior
successful result. It has no retained wire or planner/SQL authority yet.
Separate [native SQL maintenance components](authority-counted-sql-maintenance.md)
are also implemented as uninstalled source.

## One actual primary snapshot

[`evaluate_primary_radix_inputs`](../serverware/authority_radix_mutation.py)
uses the same private engine as the existing batch and membership APIs. It
returns `PrimaryRadixMutationInputs`: the genuine batch result plus the exact
engine-owned selected rows, before proofs and mutations. Those dictionaries
passed real proof reconstruction, full OLD-row CAS, lifecycle/key checks and
primary delta evaluation. No second independent copy of caller rows is used
for index projection, and the existing primary result, wire and metrics are
unchanged.

The outer observation is frozen, but its nested dictionaries remain mutable.
Consumers must call the evaluator themselves and use its local returned values
without exposing or modifying them during projection. No API accepts a
previously successful observation as a substitute for actual proof inputs.
Inventories join by exact business address, not their tuple positions.

The combined evaluator snapshots all counted heads/frontiers before invoking
that primary engine. It then uses only the engine-owned mutations and proofs:

- OLD commitments come from verified primary proofs.
- NEW commitments are the actual AuthenticatedRow/v1 hash of the same owned
  after image, charged once per nonnull indexed after image.
- Indexed keys must have exactly the source `id` column. The verified
  BusinessKey/v1 digest supplies the counted key suffix; no caller-selected
  primary commitment or projection callback is accepted.

## Complete affected-profile closure

`index_ids_for_table` returns the complete source-defined set, not a subset
chosen by the current query. The eleven fixed profiles cover credentials and
trust publications (three each), challenges (two), sessions, grants and
control-plane approvals (one each). For every changed indexed table, the
combined evaluator requires exactly all its profiles, sorted and unique, with
no missing or extra index inputs. A valid unindexed table adds no counted head.
This is the affected-write set, not the future operation's complete counted
root vector: queried but unwritten index dependencies will also need explicit
unchanged-head admission in the versioned protocol.

Every nonnull OLD/NEW image goes through the real fixed projector, including
images excluded from that profile. Invalid referenced fields are not hidden by
a nonmembership result. A full-row-only change updates each member leaf's row
commitment even when its partition and ordering fields stay the same.

The proposed maintenance revision rule is explicit:

| One primary mutation event | Counted paths | Head revision increment |
| --- | --- | --- |
| Neither image is a member | None | 0 |
| Enters or leaves membership | One | 1 |
| Both members, same key, including identical leaves | One | 1 |
| Both members, changed partition/order key | Old removal and new insertion | 1 |

An explicit DELETE/INSERT pair is two primary events, not one key-changing
UPDATE; the primary evaluator still forbids changing an original primary key
and repeated mutations of one business address. Projected path collisions and
signed64 revision overflow reject the complete batch. Each counted before and
after count must also fit its corresponding primary population descriptor;
the before descriptor is recovered from the verified after count and verified
INSERT/DELETE effects, not reread from caller roots. This is a necessary bound,
not authenticated population completeness.

## Genuine sparse before/after reconstruction

[`evaluate_index_mutations`](../serverware/authority_index_mutation.py) is the
lower-level counted engine. It accepts sorted unique `IndexLeafChange` values
and a sparse before frontier. It has no primary-row, projection, revision or
operation authority of its own.

Every target opens all proper ancestors, including targets claimed absent.
The frontier contains exactly the required present before leaves and positive
opaque immediate siblings of opened paths. Opaque records cannot cover a
target, another opened path or the root. Records are sorted, unique and
prefix-free. Missing siblings are candidates for canonical emptiness only:
the real before digest and count must reconstruct exactly before success.

Both phases' integer count/capacity checks and exact hash-work plans run before
the first counted hash. Then the engine performs the real before fold and
compares its supplied anchor, applies the explicit leaf replacements, and
performs the real after fold. Empty opened branches become implicit empty
children in their parents; an explicit zero-count child is never introduced.
Even no changes open and fold the root twice, with only positive depth-one
opaque siblings permitted. Returning the original root without reconstruction
is not a no-op shortcut.

This mutation frontier differs from a complete-range frontier: it proves the
exact changed paths and their untouched immediate siblings, not a contiguous
query interval. The separate bounded write-proof SQL producer acquires this
exact shape; it does not relabel the existing range reader as that producer.

### Write-proof acquisition and remaining planner integration

The native per-event maintenance function reads its own stored paths inside SQL;
that is not a retained planner proof producer. The pure combined evaluator
still accepts raw mutation frontiers. The separate acquisition entrypoint now
derives target keys from the same owned normalized OLD/NEW images used by the
real primary/count evaluator, with every fixed profile of every written indexed
table included. A caller-selected target subset, range interval or
already-successful result object is not accepted. Production planner acquisition,
shared trace admission and independent roots remain separate integration work.

For one profile, let `K` be the number of distinct target keys and `O` the number
of nodes in their proper-ancestor union, including the root. Target changes are
sorted and unique. Read target leaf identities separately from untouched sibling
nodes:

1. Point-read each target key, including claimed absences, with bounded batches
   and overflow sentinels. Return the complete source-pinned scalar leaf record;
   a stored leaf for an insertion-only target must not be hidden by a predicate.
2. Enumerate the sixteen immediate child identities of each opened ancestor.
   Remove identities that are themselves opened ancestors or target keys.
   These remaining identities are the only admissible opaque siblings. Read
   them in bounded exact-identity batches; do not scan their descendants or
   replace them with an arbitrary complete-range complement.
3. Validate exact profile, key/prefix/depth, commitment, count, revision and
   original primary-ID bindings. Reject duplicate/unrequested records and
   malformed matching rows. Missing nodes are empty candidates only. Merge the
   actual positive records and target leaves in sorted prefix-free order, then
   let the genuine sparse before/after evaluator reconstruct the supplied root.

With no targets, `O = 1`: the root is still folded twice and the sixteen
depth-one identities remain the sibling acquisition set. At the other extreme,
the component ceiling is `K <= 514` and conservatively `O <= 1 + 160*K`.
The exact number of possible opaque sibling identities is `15*O + 1 - K`:
the sixteen child slots per opened node exclude `O-1` non-root opened nodes and
the `K` targets. These counts concern possible read identities, not returned
positive rows or authenticated population.

Preflight physical calls, parameter bytes and retained proof work before the
first SQL statement, across **all** affected profiles and other query phases.
For the component's 256-identity batches, separate target and sibling reads need at
most `ceil(K/256) + ceil((15*O+1-K)/256)` calls before head acquisition and primary
proof reads. The maximum-size component shape can exceed the existing 4096
business-trace-entry ceiling even for one profile. That allowance also covers
other business reads and writes; the separate 69-entry allowance belongs only
to the exact global audit-capacity framework block, not index acquisition.
A component limit therefore does not promise whole-plan admission: reject an
over-budget plan without
issuing partial reads or raising the source ceiling. Empty database results do
not refund physical reads already performed.

The SQL transport preserves the range reader's exact-type CASE projection,
bounded fetch and explicit `C`-collation identity checks, without validity
predicates that conceal corrupt matching rows. Its trace needs a separately
admitted mutation-read identity, one entry per physical SELECT, not the current
range-read profile or primary proof profile. The implemented component does not
admit that production trace or establish backend query-plan cost bounds.

## Resource accounting

The lower engine admits at most 514 changed paths, covering up to two projected
paths per primary selected address under the current source ceiling. Its
ceilings are `1 + 160 * 514` opened nodes, sixteen times that many frontier
entries, and `2 * (16 * max_opened_nodes + 514)` hashes for both phases.
Actual hash metrics count leaf hashes and each real branch's missing-child
empty hashes. Child-slot work counts both phases: `2 * 16 * opened_nodes`.
Each invocation also enforces a 64 MiB closed scalar-framed input ceiling.
Callers may tighten these component limits, never enlarge them.

The combined evaluator separately caps total work at 8,000,000 hashes and
64 MiB of its defined input accounting. It reserves every counted input's
bounded descriptor/frontier bytes before primary evaluation, then clamps the
primary engine to the remaining allowance. Primary work retains its existing
cold-cache hash allowance and canonical-JSON byte metric.

For each index, the combined evaluator charges one source profile hash and a
conservative two-hash allowance per nonnull projected image, even when that
image is a nonmember and the projector returns before hashing. NEW row hashes
are charged separately. Remaining hash and byte limits are clamped before the
real lower-engine call; its actual two-phase metrics are then accumulated.

The initial frontier reservation exactly matches the lower engine's leaf and
opaque scalar framing. Only the current frontier's reservation is credited
when setting that call's byte limit; all other frontiers stay reserved. The
accumulator then adds the lower engine's actual input bytes minus that credit.
Thus the same frontier is not counted twice, while profile/change headers and
OLD/NEW leaf images remain charged. These are defined component metrics, not
network size, peak allocation, database execution cost or a whole-operation
permission. The existing operation/trace/work budgets still need integration.

## Dedicated counted-root vector: next integration direction

Use a separately bound counted-root vector rather than silently updating
primary-tracked `policy_authority_secondary_index_heads`. Updates to that
existing relation themselves change a primary root. Trigger-owned updates
would create hidden primary mutations; also applying a generic head mutation
would double-apply them. An owner-batch alternative is coherent only after
every writer participates in its one finalization barrier.

The dedicated direction fits the existing all-row primary trigger attachment
and legacy direct session writes without requiring such a hidden barrier. It
still requires a coordinated implementation, not a shortcut around authority:

1. Install source-owned counted leaves, nodes and dedicated heads with exact
   schema/ACL/function admission and deterministic lock ordering. Add real SQL
   projection/hash/maintenance parity for every supported base-row writer,
   with the revision rule above applied exactly once. Do not enroll dedicated
   heads as generic business mutations or grant arbitrary runtime index DML.
2. Add an explicit versioned counted before/after transition and retained query
   evidence to Snapshot/v4. Python admission, planner/capability/witness
   bindings and both SQL snapshot computations must agree. Lock exact counted
   before heads before business DML and compare exact after heads before the
   terminal receipt. Preserve the current nine-frame Snapshot/v3 and primary
   transition formats for their existing meaning; do not silently widen them.
3. Bound or deliberately replace every legacy maintenance path. OIDC session
   pruning and unbound-session bulk revocation currently contain unbounded
   predicate DML. Row triggers can keep those writes atomic with the index,
   but cannot make the transactions bounded. Do not silently add a LIMIT,
   freeze legacy permissions, or claim only the new kernels cover all writers.
4. Install an authenticated bidirectional population under a separately
   admitted fence/checkpoint and writer lock. Bind primary and counted roots,
   source/profile/schema identities and independently retained one-use ancestry.
   Missing storage is not permission to regenerate an accepted root. Current
   root authority, trusted time and rollback resistance remain external trust
   requirements, not properties created by these pure hashes.

The broader [storage integration contract](authority-index-storage-integration.md)
retains the all-writer, head-effect, bootstrap and versioned-evidence obligations.
No build, parser, test or PostgreSQL execution is claimed by this document.
