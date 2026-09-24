# Acquiring counted-index write proofs

## Scope

[`authority_index_mutation_reader.py`](../serverware/authority_index_mutation_reader.py)
acquires the sparse before-tree evidence needed to evaluate an entire batch of
indexed primary mutations. It reads target leaves and untouched immediate
siblings, then invokes the actual counted before/after evaluator. This is not
the [complete-range reader](authority-index-storage-integration.md#bounded-frontier-production):
a write proof follows changed paths, not a contiguous query interval.

The component is source-only, **unbuilt and unexecuted**. It is relative to
supplied before roots and revisions. It neither discovers nor authenticates a
current checkpoint, installs storage, maintains SQL indexes, attaches triggers
or enables an operation. The production planner still rejects complete-index
queries and does not admit these counted-table trace entries.

## Raw inputs and genuine computation

`acquire_indexed_primary_batch` accepts a cursor and trace sink, raw primary
contracts/roots/selected rows/proofs/mutations, before-head descriptors and
the existing bounded indexed-evaluation limits. It accepts no caller-selected
target keys, profile subset, prepared mutation plan or successful-verifier token.
Returned data includes acquired immutable frontier records and the genuine
combined result; neither is an authorization capability.

Before-head descriptors are owned before primary verification. The actual
primary engine then owns and verifies the supplied primary inputs once. Every
fixed index of each written indexed table is required, including profiles in
which both OLD and NEW are nonmembers. The real existing projection body
derives each target from those same verified row images. A full-row NEW digest
is computed once per row, not separately for every index.

Private factoring in
[`authority_indexed_mutation.py`](../serverware/authority_indexed_mutation.py)
shares the genuine primary, projection and sparse-evaluation bodies. The
existing public pure evaluator retains its original snapshot and alternating
per-index prepare/evaluate order, budgets and frontier reservation credits.
Acquisition prepares all affected profiles before SQL so it can preflight the
whole read schedule; this does not introduce a second proof recipe.

## Exact SQL evidence

For each profile, let `K` be the number of unique target keys and `O` the number
of distinct proper ancestors of those keys, including the root.

1. Point-read every target leaf identity, including insertion-only targets.
   A conflicting present leaf must not disappear behind an OLD-row predicate.
2. Enumerate the sixteen immediate children of every opened ancestor, excluding
   opened ancestors and target keys. These are the only admissible opaque
   sibling identities: exactly `15*O + 1 - K` possible records.
3. Read those sibling identities in bounded exact-identity batches. Do not scan
   descendants or substitute the range reader's outside-interval cover.
4. Validate the complete source-pinned scalar records, including original
   primary-ID commitments, revisions, depths, prefixes, digests and counts.
   Merge the actual positive records and invoke real sparse reconstruction.

With no targets, the root is still opened and all sixteen depth-one identities
are queried. Missing nodes are empty candidates only: the reconstructed digest
and count must still equal the supplied before root. Missing evidence for a
populated subtree therefore cannot become successful absence.

Queries use fixed tables/columns and bound identity parameters, at most 256
identities per batch, an overflow sentinel and bounded fetching. Malformed,
duplicate, unrequested, crossed-profile or future-revision records are rejected.
SQL must not filter malformed matching rows into apparent absence. Every
physical SELECT has its own trace entry; a loop is not one read.

## Budgets and their limits

All affected profiles share one acquisition budget. Its source ceilings are
4096 physical reads, 4 MiB of scalar-framed SQL parameters and 4 MiB of returned
scalar transport. Private composition can tighten those limits and retain prior
spending; it cannot grant a fresh per-index allowance. Parameter and returned
scalar metrics are defined work measures, not PostgreSQL wire bytes, parser
memory or database execution time.

Before the first acquisition SELECT, preflight the complete target/sibling
schedule, planned parameter work and bounded retained sparse-proof work against
the remaining budgets. Per-profile maxima do not imply that their combination
is admissible. Source hash and byte ceilings are not raised to fit an input.

Preflight holds room for every possible positive sibling's sparse framing and
at most `2*(16*O + K)` fold hashes per profile. Returned scalars are admitted
incrementally while preserving room for the remaining parameters and proof.
Releasing the hold refunds no spent work. Consequently, a budget equal to an
earlier invocation's observed total need not pass conservative preflight.

Actual acquisition parameters and returned scalar work also consume the same
remaining indexed 64 MiB ledger; computation retains the same 8M-hash ceiling.
The returned primary ID and full leaf must match the genuinely verified OLD
image and its real projection, without a redundant BusinessKey hash.
Only an already charged frontier's exact sparse scalar framing receives
the existing evaluator's reservation credit. SQL transport is neither that
framing nor refundable proof work. Failed invocations must be discarded, not
retried using a partially charged ledger.

`result.metrics.input_bytes` and `metrics.input_bytes` are this invocation's
shared-ledger delta, including head capture, SQL parameters and returned scalar
framing as well as genuine proof work. The acquisition metrics separately expose
those components; `cumulative_*` includes prior private-composition spending.
The persistent private budget rejects changed engine limits and any reuse after
failure. The public entrypoint always creates its own bounded invocation.

This is a component budget, **not production whole-plan trace admission**.
The planner's 4096 business entries must also cover head acquisition, primary
reads/proofs and writes. Its separate 69-entry global-audit allowance is not
available for counted-index work. Future integration must preserve that actual
shared accounting and version the new closed trace identities; this component
does not bypass the current trace or registry guards.

## Evidence and remaining integration

The [20 authored component cases](../scripts/test_authority_index_mutation_reader.py)
use independently built primary/counted trees and a deterministic stored-row
responder. Primary verification, projection and sparse folds are genuine;
the responder is **not PostgreSQL**, and SQL execution/parity remain unproved.
Six additional authored cases in the existing
[native counted suite](../scripts/test_authority_counted_maintenance_postgres.py)
exercise unchanged SQL through a real cursor after independently seeding a
rollback-owned canonical namespace. They deny any pre-existing namespace and
make no currentness or installed-storage claim. These cases have not run either.
Returned observations do not prove that a production writer maintained the
fixture's synthetic population.

Remaining work includes actual prepared PostgreSQL execution, admitted storage
and all-writer maintenance, independent before-vector/time/capability authority,
head and primary-proof acquisition, shared planner trace integration and
coordinated versioned persistence/replay/executor transport. The original
verification prerequisites and complete frozen source/artifact closure remain
mandatory before any build or test execution. No production-readiness or
activation claim follows from this source checkpoint.
