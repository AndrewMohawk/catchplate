# Native counted-index maintenance component

Status: source-implemented, unbuilt and unexecuted. The
[installation integration](authority-counted-installation.md) now wires these
definitions into PostgreSQL bootstrap and the real primary-tree row trigger.
No runtime installation or planner/executor counted-query admission is proven.
Direct fixture JSONB images remain component inputs, not independently current roots.

## Fixed event boundary

[`counted_maintenance_sql.py`](../catchplate/authority_store/counted_maintenance_sql.py)
defines `catchplate_policy_authority_counted_apply_event(table, operation,
old_row, new_row)`. Only the six source-indexed tables and normalized INSERT,
UPDATE and DELETE shapes are accepted. UPDATE must preserve the exact text ID;
a primary-key change requires the primary trigger's DELETE/INSERT normalization.
There is no caller-selected profile subset, root, frontier, successful verifier
result, adjustable limit, or missing-head initialization path.

The dispatcher derives every fixed profile for the table, locks/checks all
required heads in index-ID byte order, and only then invokes real per-profile
maintenance. This includes profiles for which both row images are nonmembers.
Bounded head projections preserve malformed fields as rejecting sentinels;
missing or duplicate heads deny. No exception is swallowed or transaction
committed. Failure in a later profile rolls back earlier effects of that same
SQL statement. Separate DELETE and INSERT calls are not an atomic-pair API.

## Actual per-profile update

[`counted_path_sql.py`](../catchplate/authority_store/counted_path_sql.py)
defines the invoker `catchplate_policy_authority_counted_apply_index`:

1. Measure both full rows with the real bounded wire walker; validate actual
   source projections even for nonmembers. Derive the genuine BusinessKey/v1
   identity independently of membership.
2. Lock/recheck the exact source head, projection manifest, revision, root and
   empty-count convention. Check the unique business identity and exact target
   leaves. OLD commitment mismatches, missing OLD leaves and occupied new
   insertion paths deny. A stale same-ID leaf also denies a nonmember event.
3. Open the union of proper target ancestors and read their immediate children
   in fixed bounded batches. Validate every returned node's identity, digest,
   count, depth capacity and revision. Malformed matching records are not
   filtered into absence.
4. Reconstruct genuine BEFORE and AFTER digests/counts from actual leaves and
   unchanged opaque siblings. Compare each opened stored cache node and target
   depth-160 node with its computed BEFORE value, then compare the complete
   BEFORE root/count with the locked head. Inconsistent caches are not repaired
   silently. Even a zero-target event performs both root folds.
5. Only after successful calculation, remove departed leaves before inserting
   their replacement, upsert positive touched nodes, remove zero-count touched
   nodes and compare-and-set the head. Untouched records retain their revisions.

Each profile advances once if either image is a member, including an equal-row
UPDATE or partition move. Two nonmembers advance zero and write nothing; an
explicit DELETE/INSERT pair consists of two events. Overflow denies before
publication. All stored nodes remain positive-count; the root is stored only
in its head, not as a depth-zero node.

## Component bounds

| Per profile/event | Fixed source ceiling |
| --- | ---: |
| Target keys | 2 |
| Opened proper prefixes, including root | 320 |
| Immediate-child slots | 5,120 |
| Node identities per physical batch | 256 |
| Node batches | 20 |
| Conservative counted/projection/identity hash work | 10,253 |
| Joint OLD/NEW input JSON nodes | 1,000,000 |
| Stored scalar-framed input | 4 MiB |
| Joint measured row bytes plus stored scalar-framed input | 64 MiB |

The dispatcher has at most three profiles and additionally computes one
canonical-empty hash per required head. The per-profile ceilings are not a
shared operation/transaction allowance. SQL projection and serialization walk
the inputs more than once; the JSON-node ceiling describes admitted input
shape, not an exact total traversal counter. Scalar-byte accounting excludes
PostgreSQL wire framing, outbound parameters and executor/parser/detoast memory.
Bounded returned records do not establish query-plan or allocation isolation.

Production integration still needs aggregate SQL/hash/byte/evidence accounting
across every phase and writer. These constants do not raise the existing outer
plan budget or authorize arbitrary multirow legacy writes.

## Authored native coverage and remaining integration

[`test_authority_counted_maintenance_postgres.py`](../scripts/test_authority_counted_maintenance_postgres.py)
contains 32 unrun methods using real definitions in rollback-owned PG16 schemas
and independent complete-tree oracles. The original 18 compare all head/leaf/node values
and revisions across the eleven profiles, membership/partition moves, equal
updates, deletion, corruption rejection, overflow and later-profile rollback.
Their explicit fixture population is not authenticated bootstrap evidence.
Six reader methods acquire actual production-qualified bounded queries; six
trigger methods use the real primary row-trigger and counted dispatcher for
business INSERT/UPDATE/DELETE, including later-failure atomicity. Two installer
methods cover fresh empty genesis, unchanged populated restart, populated
fresh-store refusal and missing-head refusal. Synthetic business relations in
these cases are not the full production foreign-key schema.
The catalogue check pins its session's identifier-quoting mode and compares the
exact resulting search-path setting; it does not discard quote or whitespace
differences to make the assertion pass.

No maximum-slot, memory-allocation, concurrency, installed-trigger provenance,
durability or production-currentness claim follows from these authored cases.
All tests await the separately admitted source-freeze/preparation workflow.

The remaining coordinated work is described in the
[storage integration contract](authority-index-storage-integration.md): native
verification of the authored canonical/scratch schema, ACL installation and
real all-writer OLD/NEW hooks; independently admitted empty genesis or
bidirectional populated restage; shared operation
limits and lock order; versioned primary/counted/query root vectors and receipts;
and independently operated current-root enrollment/advancement. The existing
terminal business-result witness is not a current primary/counted-root service.
