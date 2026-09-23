# Counted write-transition document

## Implemented boundary

[`authority_counted_root_transition.py`](../serverware/authority_counted_root_transition.py)
now derives an operation-bound, closed document from the actual
[combined primary/count mutation evaluator](authority-index-mutation.md).
It records the complete primary transition and every fixed counted profile of
each mutated indexed table. Its scope is explicitly `write-effects-only`.

This is unbuilt, unexecuted component source. It does not admit operation
intent, authenticate supplied before roots or historical index population,
carry complete-query/read-only counted dependencies, or activate a planner,
database trigger, receipt, witness or startup kernel. It is not Snapshot/v4.

## API and ownership

`derive_counted_root_transition` accepts the operation, business and
authorization before-root vectors, selected rows, actual before proofs,
normalized mutations and counted mutation inputs. Physical table contracts and
limits come from the source operation, not caller parameters. Both primary
before-root vectors are copied as bounded exact scalars before any context
hash or primary-root constructor runs.

The wrapper invokes `evaluate_indexed_primary_batch` exactly once. That engine
owns counted heads/frontiers before primary evaluation and derives projections
only from the primary engine's actual verified snapshots. The wrapper retains
that engine's primary result by identity; it does not rerun the legacy primary
deriver or accept a supplied successful result object.

The returned `DerivedCountedRootTransition` contains the actual primary result,
immutable canonical document bytes, its digest and separate packaging metrics.
`json_projection()` returns a fresh graph. This freely constructible observation
is not an authority token and cannot replace inputs to verification.

`verify_counted_root_transition` snapshots the complete bounded claimed
document before hashing, validates its shape, genuinely derives the transition
once from the original proof inputs and compares the entire canonical document.
Proof failures are reported as `CountedRootTransitionError` with their original
cause. `validate_counted_root_transition` and
`counted_root_transition_digest` perform only structural validation/digesting;
neither verifies proofs or authorizes a write.

## Closed wire

The schema is `serverware.policyAuthorityCountedRootTransition/v1`; the profile
is `serverware.policyAuthorityCountedRootTransitionProfile/v1`. Exact fields are:

- `schema`, `profile`, `scope`, `operation`, `countedProfile` and
  `projectionManifestDigest` bind this source contract.
- `primaryTransition` retains the unchanged PrimaryRootTransition/v1 schema
  and primary profile v2, including all source-required business and
  authorization roots, even unchanged/read-only primary relations.
- `indexBeforeHeads` and `indexAfterHeads` are matching sorted unique inventories.
  Each head has exactly `indexId`, `table`, `projectionDigest`, `indexRevision`,
  `rootDigest` and `leafCount`.
- `metrics` binds the genuine combined engine's per-index metrics,
  `contextHashes`, `projectionHashAllowance`, `newRowHashes`, `hashWork` and
  `inputBytes`. Per-index entries carry identity, changes, frontier entries,
  opened nodes, both-phase child slots/hashes and input bytes.

Revisions/counts are exact nonnegative signed64 integers; booleans and numeric
aliases reject. Count zero is equivalent to the profile's canonical empty
root, and revision zero requires emptiness. All fixed profiles of a written
table participate, including nonmember/no-change profiles. The actual engine
enforces the input inventory; structural closure alone cannot prove which
tables were mutated.

One normalized primary event advances each participating member profile once,
including an equal UPDATE. A partition move has two changed paths but one
revision increment. Both nonmember images leave that head unchanged. Explicit
DELETE/INSERT events advance separately; an UPDATE cannot change its primary
key. Counts must fit corresponding primary population descriptors. These are
necessary relationships, not independent population/currentness evidence.

Canonical wire JSON uses the existing ASCII JSON encoding and the legacy
domain-plus-NUL digest family: the schema domain precedes the length-framed
document bytes. Counted projection descriptors retain their different
length-framed-domain hash family; the two must not be interchanged.

## Bounded packaging and computation

The wrapper reserves 90 hashes before invoking the engine: a cold primary
descriptor allowance of 66, eleven source profile hashes, eleven empty-root
hashes, one projection-manifest hash and one final document digest. Context is
reused across validation and assembly. The combined engine retains its own
separate conservative cold-cache accounting; a warm cache grants no discount.

The operation's selected-row and mutation ceilings constrain primary inputs.
Counted changed-path capacity is twice the smaller of those ceilings, because
the real primary engine requires distinct selected mutation addresses. It is
not twice an independently larger mutation ceiling.

The source aggregate ceilings remain 8,000,000 hashes and 64 MiB of defined
input accounting. Before the engine call, its limits are reduced by the
90-hash allowance and a 256 KiB document reserve. Separate returned packaging
metrics record the allowance, actual document bytes, total hash work and total
input bytes; they are not self-referential fields in the hashed document.

Claim copying incrementally charges exact compact JSON scalar/container bytes,
with bounded depth, node count, arrays, objects and ASCII scalars. It rejects
over-limit graphs before retaining the next child. These limits do not bound
an upstream parser's allocation, total process memory, SQL cost or the work of
future query/pre-kernel phases.

## Authored controls and remaining integration

[`test_authority_counted_root_transition.py`](../scripts/test_authority_counted_root_transition.py)
contains 20 authored, unexecuted methods. Independent tree, projection, wire,
digest and metric oracles cover actual single-call evaluation, source root and
write-profile closure, equal updates, normalized key changes, genuine proof and
frontier rejection, recomputation of altered claims, immutable output, ownership
at delegated real hash boundaries, resource accounting and revision overflow.
The aggregate copier control uses an oversized malformed graph; it does not
claim that a valid document reaches the 256 KiB ceiling or exercise a valid
maximum-size 64 MiB proof batch. This pure suite does not change native suite
counts, deadlines or production exclusions.

The separate [complete read/write composer](authority-complete-read-write.md)
now computes the union of write heads and every source complete-query head,
including empty-query and read-only dependencies. It uses one shared before
descriptor per profile, preserves read-only after heads and invokes the actual
query joins and indexed writer under a shared operation budget. It does not
produce retained proof transport or expand this write-effects-only document.
Production still needs an explicitly versioned protocol binding that full
vector through planning, SQL before/after checks, receipts and independent current-root
authority. The existing nine-frame Snapshot/v3 is not widened by this component.
See the [storage integration contract](authority-index-storage-integration.md)
for all-writer maintenance, schema/ACL admission and authenticated population.
