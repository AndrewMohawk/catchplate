# Complete-query and counted-write composition

## Current boundary

This integration batch is implemented and source-reviewed, but unbuilt and
unexecuted. It is not a verified runtime, activated planner path or
operation-authority decision. The existing
[query batch](authority-complete-query-batch.md) and
[indexed mutation evaluator](authority-index-mutation.md) provide its genuine
verification phases; neither accepts a prior successful result as authority.

The scope remains the five complete-query roles for explicit
`webauthn.credential.revoke`. The purpose of the combined entry point is to
verify their read evidence and proposed writes against one identical set of
before descriptors, with one input ownership boundary and one work budget.
It does not establish that an authenticated caller requested those writes.

The entry point is `verify_complete_read_write_batch` in
[`authority_complete_read_write.py`](../serverware/authority_complete_read_write.py).
Its counted inputs use `CompleteReadWriteHead` for the one before-head union and
`CompleteWriteFrontier` for each required write profile. Query declarations and
frontiers retain their existing exact DTO types. These constructors describe
data, not verified capabilities.

## One graph, two kinds of proof

Before any hashing constructor or verifier, capture the operation, arguments,
cutoff, declarations, full primary before-root vectors, global selected rows,
primary proofs, mutations, counted head union and both kinds of raw frontier.
The retained counted union must be exactly:

`four complete-query read profiles UNION every fixed profile of each written table`

One sorted head entry supplies every use of a profile. A profile shared by a
query and a write cannot carry different revision, digest or count descriptors.
All fixed profiles of a written table remain required even if the old and new
rows are both nonmembers of a particular profile. Empty query roles also remain
required.

This operation can write at most eight fixed profiles: three credential, two
challenge and one each for sessions, grants and approvals. Its four read
profiles are already within that set. The generic eleven-profile input ceiling
does not permit adding the three publication profiles from another operation.

The genuine global membership evaluator owns the selected rows and proofs used
by each real range/primary join. The genuine indexed writer then verifies the
same owned global evidence together with the owned mutations. Its repeated
primary verification is real work and must be charged again. The combined
after vector uses the writer's actual after heads for written profiles and
preserves read-only heads exactly.

The input does not contain an independently supplied per-query primary subset,
separate write-side before heads, a verified-query token, a verified-write
token, a replacement evaluator or a caller-expanded budget.

## Source admission and limits

Mutation wrappers must use an actual source template for this operation, with
matching table, mutation kind, exact full-row CAS predicate and cardinality one.
The lower primary engine's nonempty template identifier is insufficient for
this operation-bound admission. Actual key, row, proof, lifecycle and source
write-access checks still belong to the genuine primary evaluator.

The existing business limits are 192 selections and 136 mutations. At most one
additional selection and mutation may use the exact global audit-counter
address, for totals of 193 and 137. A counter-like name, kind or partition does
not earn either allowance. This budget classification does not establish
initialized counter state or admit audit capacity.

Preserve the existing 4 MiB business selected-envelope and 4 MiB plus 8192 byte
combined selected-envelope bounds. There is no invented 4 MiB mutation-envelope
limit. Ownership, all real proof phases and additional defined measurement work
share 8,000,000 hashes, 64 MiB of input work and 1,000,000 charged JSON nodes;
remaining phase limits must be clamped before invoking an evaluator.

The query wrapper retains its conservative 95-hash context allowance. Each
union head that is not a read head adds one source-profile hash and one
canonical empty-root hash; read heads reuse the query phase's already checked
context. At most four extra heads are source-admitted here, so that additional
context is at most eight hashes. The genuine indexed writer separately charges
its own primary, profile, row-projection and sparse-fold work. No 90-hash
write-document or 256 KiB packaging reserve is claimed: this component does not
produce that wire document. The standalone query API's capture representation and metric
semantics are unchanged by the shared private factoring.

Independent phase ceilings are not a promise that every maximum can fit in one
batch. In particular, repeated full primary-proof traversals plus all query
joins can exhaust the shared node or byte budget before the declared row
ceilings. Reject that batch; do not refund real repeated work, accept an earlier
success token, truncate evidence or enlarge the budget to force admission.

A single write frontier can have a much larger source ceiling than a query
frontier. Before constructing normalized terminal dictionaries, bound their
combined minimum JSON-node cost across all query and write frontiers. Each
closed four-field leaf or opaque record requires at least nine nodes including
its dictionary and keys. Reject a graph that cannot fit before expanding that
intermediate representation; later incremental ownership still checks actual
bytes, nodes, depth and exact lossless JSON types. These are component work
bounds, not a guarantee about arbitrary upstream parser allocation or total
process memory.

## Authored regression coverage

[`test_authority_complete_read_write.py`](../scripts/test_authority_complete_read_write.py)
contains 20 authored, unexecuted methods. Independent before/after populations
and accounting oracles cover actual seven/eight-profile unions, empty queries,
unchanged read-only heads, required nonmember profiles, exact source templates,
corrupted raw proofs and mutation images, input ownership before the first
hash, early frontier-normalization rejection and aggregate work accounting.
Delegated call observations retain the real global membership, five joins and
one indexed writer, including its genuine repeated primary verification.
Their actual phase limits are compared with independently advanced remainders.

Separate genuine cases exercise 193 absent selections with empty queries and
no writes, and 136 ordinary mutations plus one exact framework mutation. These
do not claim simultaneous maximum load or initialized audit capacity. A 5 MiB
NEW image in an unindexed row distinguishes the shared input budget from the
smaller selected-envelope limit; it is not kernel or database admission.
No test ran or passed. Native-suite counts, deadlines and exclusions are
unchanged.

## Still required before planner activation

The combined observation is data, not signed authority or permission to mutate
storage. The separate [retained revocation bundle](authority-revocation-proof-bundle.md)
now preserves raw frontiers, primary evidence and full observations, and binds
the complete before/after union into a closed versioned transition. Its replay
genuinely recomputes that evidence; encoding and hashing share the whole budget.
This pure component does not persist or admit planner transport.

[Measured query-observation validation](authority-query-read-accounting.md)
provides genuine shared-body accounting. The separate, unexecuted
[mixed revocation composer](authority-revocation-read-write.md) owns the larger
raw graph once, binds the actual source program and full point keys, calls this
component's private proof worker once, and compares observations with actual
complete-query leaf order. The standalone API and its accounting are unchanged.

The existing primary transition and nine-frame Snapshot/v3 remain unchanged.
Planner, executor, SQL, receipts and historical replay must move together to an
explicit new protocol; optional extra fields on v3 are not an upgrade path.
Planner integration of mixed query closure, kernel admission, audit capacity,
mutation-proof SQL acquisition, schema and all-writer maintenance, authenticated population,
trusted time/intent and [independent current roots](authority-current-root-witness-integration.md)
remain separate required integrations. None is supplied by a successful pure
read/write calculation alone.
