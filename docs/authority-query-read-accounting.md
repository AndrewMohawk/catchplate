# Cumulative query-observation validation work

## Boundary

`validate_query_reads_measured` in
[`authority_query_reads.py`](../serverware/authority_query_reads.py) adds one
cumulative work budget to genuine query-observation validation. It reuses the
existing source snapshot, record reconstruction, address association, deferred
value resolution and observation capture. It does not replace those checks
with a metric calculation or accept a previously successful result.

This is source implementation only: unbuilt and unexecuted. The actual typed
planner now shares this ledger across its observation-bookkeeping phases; the
mixed revocation composer also uses the genuine measured validator. The original public
`validate_query_reads` keeps its existing admission rules and return type.
The measured entry point deliberately has additional cumulative-work limits.

Query observations remain bookkeeping. They do not authenticate selected rows,
evaluate ordinary predicates, prove a complete range, regenerate an operation's
exact source program, authorize mutations or establish current roots and time.
In particular, the generic bookkeeping contract is not a substitute for
source-bound full-primary-key admission on both present and absent point reads.

## API and units

The measured call accepts the operation, source query tuple, immutable
`QueryRead` tuple, global selected-row tuple and exact
`QueryReadValidationLimits`. Its `QueryReadValidationResult` contains owned
query snapshots, freshly checked immutable observations and
`QueryReadValidationMetrics(hash_work, input_bytes, json_nodes)`.

Limits may only tighten the source ceilings:

| Resource | Source ceiling | Meaning |
| --- | ---: | --- |
| Hash work | 8,000,000 | Actual prepared profile and BusinessKey SHA-256 calls |
| Input work | 64 MiB | Defined cumulative copy, encoding and record-frame work |
| JSON nodes | 1,000,000 | Repeated JSON walks, including dictionary keys |
| JSON depth | 128 | Fixed source traversal bound, not caller-expandable |

Limits are revalidated at entry, even for a constructor-bypassed frozen object.
Booleans, missing fields and values above the source ceilings are not valid
limits. Remaining budget is checked before the corresponding serialization or
hash. No helper starts a new cumulative allowance. Existing local copy,
retained-record, query-count, address-occurrence and returned-row guards remain
in force as well.

The work helper has only standard-library imports. Core transition code already
imports query-record types; accounting must not introduce an eager reverse
import of the transition core or a database/registry dependency.

## Charge repeated work, not just the final records

Canonical encoding first measures the exact compact representation without
allocating the encoded buffer. That traversal is work. The actual encoding is
a second pass and is reserved separately before serialization. Dictionary keys,
containers and scalar values count as nodes on each walk. ASCII JSON is used
for query records; fixed projection descriptors retain their actual UTF-8 JSON
profile. Neither representation silently substitutes for the other.

Source-value copying retains its existing conservative canonical-size units,
including separator allowances. Hidden copies and encodings also count:
`SelectedRowFieldReference` construction copies its key into `canonical_bytes`,
and its contract serializer makes another shallow key copy. Declared and
resolved contracts, repeated complete-query snapshots inside `close_queries`,
and repeated reference resolutions are not free because their inputs were
seen earlier.

Immutable record reconstruction still validates the actual fields. Its bounded
ASCII scans, address association and comparison passes use defined record-frame
byte charges rather than claiming that immutable byte strings are new JSON
trees. The byte metric is therefore cumulative work, not the serialized size of
one retained bundle. It is not a count of interpreter allocations, every CPU
instruction, external parser memory or whole-process memory.

For successful validation, an independent hash cross-check is:

`hash_work = 8 * complete_declarations + global_selections + observed_address_occurrences`

The eight profile hashes per complete declaration come from its initial
snapshot and contract, source closure's repeated snapshot, resolution snapshot,
two resolution-shape contracts and two capture contracts. Every global address
and every captured address occurrence performs its real BusinessKey hash.
The implementation reserves at the actual call sites; the formula is an oracle,
not permission to skip the genuine calls. Overlapping observations continue to
spend work for each occurrence.

## Ownership and next integration

Returned query dictionaries are detached source snapshots, not recursively
immutable capabilities. Returned records and metrics are frozen observations.
The measured validator does not snapshot every caller-supplied full row: it
reads original keys and fields used by source references. Its caller must
provide privately owned selected rows when composing it with proof validation.

The [complete read/write composer](authority-complete-read-write.md) already
owns its raw evidence before its genuine proof phases. A mixed consumer must
feed that same owned graph into measured observation validation and debit
the same outer budget. It must additionally bind the entire source-generated
mixed query program, compare complete observations with actual joined leaf
order, enforce exact point-read keys for presence as well as absence, and
retain every empty observation. Neither independently successful component is
a reusable authority token. The separate
[measured source generator](authority-revocation-query-work.md) now accounts the
genuine recipe's own work. The unexecuted
[mixed revocation composer](authority-revocation-read-write.md) connects both
workers to genuine proof computation and adds the full-key and joined-order
bindings; it does not activate this path in the planner.

Raw transport capture, retained-bundle encoding and hashing, compact transition
packaging, kernel/audit-capacity admission, SQL acquisition and the coordinated
versioned planner/executor protocol remain separate work. Snapshot/v3 and its
nine frames are unchanged; the complete-query planner gate remains closed.

## Actual planner bookkeeping integration

Source `.30` binds `PLANNER_QUERY_BOOKKEEPING_CONTRACT` into the operation and
schema-source digests. It is an additional cumulative admission limit, not just
telemetry or a reinterpretation of signed business `workUnits`. Schema version
9, the closed v3 payloads, and their field inventories remain unchanged.

`MeasuredPlanner.derive` creates one invocation-private `_ValidationWork` for a
typed program, using the fixed hash/input/node limits above. That same object
passes through source snapshotting, staged reference-source bookkeeping,
resolution, capture and growing-prefix checks, then both whole-observation
validations: at the end of acquisition and after actual primary verification
replaces selected rows with its owned snapshots. Repeated scans and copies
remain charged even when a previous phase examined identical records.

The real reference, resolution and capture bodies are shared private workers;
their existing public facades preserve the unmeasured behavior and return types.
The planner does not call the standalone measured entry point between phases,
because that entry point would start a new ledger. It does not store the mutable
ledger in PlanningState, retained proofs, signatures or durable receipts.

The staged collector binds the supplied meter identity and retains its own
separate proof and cache-stamp budgets. Bookkeeping exhaustion aborts planning;
it is never handled by resetting limits or retrying the next query. A poisoned
or reentered collector cannot return success even when a nested rejection was
caught by an observer. That does not interrupt a currently running bounded proof
producer or establish a whole-process execution bound.

This ledger excludes source query generation, full-row conflict comparisons,
SQL/transport, primary proof construction and verification, cache stamps, kernel
execution, range/mutation proofs, and final payload packaging. Integrating those
phases under coordinated remaining-work limits is still required. Query records
remain observations, not complete or current authority; complete-index queries
still reject before business/proof SQL and the registry remains closed.

## Authored coverage

[`test_authority_query_reads_measured.py`](../scripts/test_authority_query_reads_measured.py)
retains its original 18 authored methods using independently encoded mixed observations:
present point reads, deferred
values and absence keys, ordinary empty results, all five complete roles and
ordered overlap. It observes the real resolution/capture/closure and SHA calls,
checks independently calculated byte/node/hash totals, tightened exact budgets
and one-unit denials, and exercises cumulative
repeated-reference work under the unchanged source ceiling. Legacy admission
and the distinction between observations and proof authority remain explicit.

Eight additional incremental-pipeline cases (26 methods total) exercise the actual shared workers and
independently count repeated snapshot/reference/resolve/capture/prefix/final
validation work. Staging cases cover shared meter identity, cache-hit charges,
exhaustion before proof acquisition and monotonic failure. Source-linkage checks
pin actual planner wiring without importing a substitute registry. Two genuine
planner-worker cases are retained in the startup-dependent suite; they cannot
run successfully until its real registry imports, and even then their empty SQL
responder is not native PostgreSQL evidence.

All prior method IDs are preserved. The related staging fixture has 27 methods,
planner/capacity source linkage has 16, table/source-contract linkage has 19,
and the startup suite has 32. These are authored inventories, not test results;
the existing native inventory remains 252 methods across fourteen suites.

These tests have not run. No runtime, database, startup or production claim is
established by their source or registration. Native-suite counts, verification
deadlines and blocked prerequisites are unchanged.
